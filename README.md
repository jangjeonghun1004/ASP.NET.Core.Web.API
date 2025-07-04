ASP.NET Core Web API with Swashbuckle and JWT Authentication
============================================================

	1. Swashbuckle.AspNetCore 패키지 설치한다.
	```bash
	dotnet add package Swashbuckle.AspNetCore
	```
	
	2. program.cs 파일에 Swagger 설정 추가
	```csharp
	// --------------------------------------------------------------------------
	// Swagger/OpenAPI 문서 및 UI 생성 서비스 추가
	// (Swashbuckle.AspNetCore 패키지에서 제공)
	// --------------------------------------------------------------------------
	builder.Services.AddSwaggerGen(c =>
	{
		c.SwaggerDoc("v1", new OpenApiInfo { Title = "My .NET 9 API", Version = "v1" });
	});
	// --------------------------------------------------------------------------


	// Configure the HTTP request pipeline.
	if (app.Environment.IsDevelopment())
	{
		app.MapOpenApi();
		app.UseSwagger();     // <--- swagger.json 파일을 서비스 (OpenAPI JSON 생성)
		app.UseSwaggerUI();   // <--- swagger.json을 기반으로 UI를 렌더링
	}
	```

	3. Swagger ui 호출
	https://localhost:7275/swagger/index.html

	4. JWT 인증 패키지 설치
	```bash
	dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
	dotnet add package System.IdentityModel.Tokens.Jwt
	```

	5. application.json 파일에 JWT 설정 추가
	```json
	{
	  "Logging": {
		"LogLevel": {
		  "Default": "Information",
		  "Microsoft.AspNetCore": "Warning"
		}
	  },
	  "AllowedHosts": "*",
	  "JwtSettings": {
		"Issuer": "https://localhost:7000", // 토큰을 발행하는 서버의 주소 (실제 앱에서는 배포된 도메인)
		"Audience": "https://localhost:7000", // 토큰을 수신할 대상 (실제 앱에서는 배포된 도메인)
		"Secret": "YourSuperStrongAndComplexSecretKeyForJwtAuthenticationThatIsAtLeast32CharactersLong", // 토큰 서명에 사용될 비밀 키 (최소 32자 이상 권장, 매우 중요!)
		"TokenExpirationMinutes": 60 // 토큰 만료 시간 (분)
	  }
	}
	```
	
	6. Program.cs 파일에 JWT 인증 설정 추가
	```csharp
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

	// 인증 및 권한 부여 미들웨어 파이프라인에 추가 (순서 중요!)
	app.UseAuthentication(); // <--- 인증 미들웨어: HTTP 요청에서 JWT 토큰을 확인하고 사용자 신원(ClaimsPrincipal)을 구축합니다.
	app.UseAuthorization();  // <--- 권한 부여 미들웨어: 구축된 사용자 신원을 기반으로 리소스 접근 권한을 확인합니다.
	```

	7. 보호된 엔드포인트에 [Authorize] 특성 추가
	```csharp
	[Authorize] // 이 엔드포인트는 인증된 사용자만 접근할 수 있습니다.
	[HttpGet("protected")]
	public IActionResult GetProtectedResource()
	{
		return Ok("This is a protected resource accessible only to authenticated users.");
	}
	```

	8. 보호되지 않은 엔드포인트에 [AllowAnonymous] 특성 추가
	```csharp
	[AllowAnonymous] // 이 엔드포인트는 인증되지 않은 사용자도 접근할 수 있습니다.
	[HttpGet("public")]
	public IActionResult GetPublicResource()
	{
		return Ok("This is a public resource accessible to everyone.");
	}
	```

	9. JWT 토큰 생성 및 반환을 위한 엔드포인트 추가
	```csharp
	[AllowAnonymous]
    [HttpGet("GetJwtToken")]
    public IActionResult GetJwtToken()
    {
        var token = GenerateJwtToken("username", "User");
        return Ok(new { Token = token });
    }

    // JWT 토큰을 생성하는 private 헬퍼 메서드
	private readonly IConfiguration _configuration; // 구성(Configuration) 주입

    public WeatherForecastController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    private string GenerateJwtToken(string username, string role)
    {
        // appsettings.json에서 JWT 설정 가져오기
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["Secret"];
        var issuer = jwtSettings["Issuer"];
        var audience = jwtSettings["Audience"];
        var tokenExpirationMinutes = int.Parse(jwtSettings["TokenExpirationMinutes"] ?? "60");

        // 비밀 키를 바이트 배열로 변환하여 서명 키 생성
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!)); // secretKey는 null이 아니므로 ! 사용
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); // HmacSha256 알고리즘으로 서명

        // 클레임(Claims): 토큰에 포함될 사용자 정보 (사용자 이름, 역할 등)
        // 이 정보는 나중에 HttpContext.User.Claims를 통해 접근할 수 있습니다.
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),       // Subject (토큰의 주체, 사용자 고유 식별자)
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID (토큰의 고유 식별자)
            new Claim(ClaimTypes.Name, username),                   // 사용자 이름 클레임
        };

        // 역할 클레임 추가
        if (!string.IsNullOrEmpty(role))
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        // JWT 토큰 생성
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(tokenExpirationMinutes), // 토큰 만료 시간 설정
            signingCredentials: credentials);

        // 토큰을 문자열로 직렬화하여 반환
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
	```