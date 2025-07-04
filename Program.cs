using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using Microsoft.AspNetCore.Authorization; // [AllowAnonymous] ���� ���� �ʿ� (���� ����)

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddEndpointsApiExplorer(); // Swagger/OpenAPI ����
builder.Services.AddSwaggerGen(); // Swagger UI ����

// --------------------------------------------------------------------------
// Swagger/OpenAPI ���� �� UI ���� ���� �߰�
// (Swashbuckle.AspNetCore ��Ű������ ����)
// --------------------------------------------------------------------------
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "My .NET 9 API", Version = "v1" });

    // JWT Bearer ���� ��Ŵ ����
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization", // ��� �̸�
        Type = SecuritySchemeType.ApiKey, // API Ű Ÿ�� (���� ��Ŵ)
        Scheme = "Bearer", // ��Ŵ �̸� (JWT ��ū�� ���λ�)
        BearerFormat = "JWT", // Bearer ����
        In = ParameterLocation.Header, // ��ū�� HTTP ����� ��ġ
        Description = "JWT ������ ���� Bearer ��ū�� �Է��ϼ���. ��: 'Bearer {token}'"
    });

    // ��ȣ�� ��������Ʈ�� ���� ���� �䱸 ���� �߰�
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer" // ������ ������ ���� ��Ŵ�� ID
                }
            },
            new string[] {} // �� ��Ŵ�� ���� �䱸 ���� (���⼭�� ���� �� �߰� ����)
        }
    });
});

// JWT ���� ��������
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["Secret"];

// ��� Ű�� �������� �ʾҴٸ� ���� �߻�
if (string.IsNullOrEmpty(secretKey))
{
    throw new InvalidOperationException("JWT Secret key not found or is empty in configuration.");
}

// ���� ���� �߰� (JWT Bearer ��Ŵ ���)
builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // �⺻ ���� ��Ŵ
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;   // �⺻ ç���� ��Ŵ (���� ���� ��)
}).AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, // ��ū ������(Issuer) ���� Ȱ��ȭ
        ValidateAudience = true, // ��ū ������(Audience) ���� Ȱ��ȭ
        ValidateLifetime = true, // ��ū ���� �ð� ���� Ȱ��ȭ
        ValidateIssuerSigningKey = true, // ��ū ���� Ű ���� Ȱ��ȭ

        ValidIssuer = jwtSettings["Issuer"], // ��ȿ�� ������ ����
        ValidAudience = jwtSettings["Audience"], // ��ȿ�� ������ ����
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)) // ���� Ű ���� (��� Ű�� ����Ʈ �迭�� ��ȯ)
    };
});

// ���� ���� �߰�
builder.Services.AddAuthorization();


var app = builder.Build();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();     // <--- swagger.json ������ ���� (OpenAPI JSON ����)
    app.UseSwaggerUI();   // <--- swagger.json�� ������� UI�� ������
}

app.UseHttpsRedirection();
// ���� �� ���� �ο� �̵���� ���������ο� �߰� (���� �߿�!)
app.UseAuthentication(); // <--- ���� �̵����: HTTP ��û���� JWT ��ū�� Ȯ���ϰ� ����� �ſ�(ClaimsPrincipal)�� �����մϴ�.
app.UseAuthorization();  // <--- ���� �ο� �̵����: ����� ����� �ſ��� ������� ���ҽ� ���� ������ Ȯ���մϴ�.
app.MapControllers();
app.Run();
