using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using Microsoft.AspNetCore.Authorization; // [AllowAnonymous] 등을 위해 필요 (선택 사항)

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddEndpointsApiExplorer(); // Swagger/OpenAPI 관련
builder.Services.AddSwaggerGen(); // Swagger UI 생성

// --------------------------------------------------------------------------
// Swagger/OpenAPI 문서 및 UI 생성 서비스 추가
// (Swashbuckle.AspNetCore 패키지에서 제공)
// --------------------------------------------------------------------------
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "My .NET 9 API", Version = "v1" });

    // JWT Bearer 인증 스킴 정의
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization", // 헤더 이름
        Type = SecuritySchemeType.ApiKey, // API 키 타입 (인증 스킴)
        Scheme = "Bearer", // 스킴 이름 (JWT 토큰의 접두사)
        BearerFormat = "JWT", // Bearer 포맷
        In = ParameterLocation.Header, // 토큰이 HTTP 헤더에 위치
        Description = "JWT 인증을 위한 Bearer 토큰을 입력하세요. 예: 'Bearer {token}'"
    });

    // 보호된 엔드포인트에 대한 보안 요구 사항 추가
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer" // 위에서 정의한 보안 스킴의 ID
                }
            },
            new string[] {} // 이 스킴에 대한 요구 사항 (여기서는 역할 등 추가 없음)
        }
    });
});

// JWT 설정 가져오기
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["Secret"];

// 비밀 키가 설정되지 않았다면 오류 발생
if (string.IsNullOrEmpty(secretKey))
{
    throw new InvalidOperationException("JWT Secret key not found or is empty in configuration.");
}

// 인증 서비스 추가 (JWT Bearer 스킴 사용)
builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // 기본 인증 스킴
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;   // 기본 챌린지 스킴 (권한 없을 때)
}).AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, // 토큰 발행자(Issuer) 검증 활성화
        ValidateAudience = true, // 토큰 수신자(Audience) 검증 활성화
        ValidateLifetime = true, // 토큰 만료 시간 검증 활성화
        ValidateIssuerSigningKey = true, // 토큰 서명 키 검증 활성화

        ValidIssuer = jwtSettings["Issuer"], // 유효한 발행자 설정
        ValidAudience = jwtSettings["Audience"], // 유효한 수신자 설정
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)) // 서명 키 설정 (비밀 키를 바이트 배열로 변환)
    };
});

// 권한 서비스 추가
builder.Services.AddAuthorization();


var app = builder.Build();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();     // <--- swagger.json 파일을 서비스 (OpenAPI JSON 생성)
    app.UseSwaggerUI();   // <--- swagger.json을 기반으로 UI를 렌더링
}

app.UseHttpsRedirection();
// 인증 및 권한 부여 미들웨어 파이프라인에 추가 (순서 중요!)
app.UseAuthentication(); // <--- 인증 미들웨어: HTTP 요청에서 JWT 토큰을 확인하고 사용자 신원(ClaimsPrincipal)을 구축합니다.
app.UseAuthorization();  // <--- 권한 부여 미들웨어: 구축된 사용자 신원을 기반으로 리소스 접근 권한을 확인합니다.
app.MapControllers();
app.Run();
