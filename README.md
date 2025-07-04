ASP.NET Core Web API with Swashbuckle and JWT Authentication
============================================================

	1. Swashbuckle.AspNetCore ��Ű�� ��ġ�Ѵ�.
	```bash
	dotnet add package Swashbuckle.AspNetCore
	```
	
	2. program.cs ���Ͽ� Swagger ���� �߰�
	```csharp
	// --------------------------------------------------------------------------
	// Swagger/OpenAPI ���� �� UI ���� ���� �߰�
	// (Swashbuckle.AspNetCore ��Ű������ ����)
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
		app.UseSwagger();     // <--- swagger.json ������ ���� (OpenAPI JSON ����)
		app.UseSwaggerUI();   // <--- swagger.json�� ������� UI�� ������
	}
	```

	3. Swagger ui ȣ��
	https://localhost:7275/swagger/index.html

	4. JWT ���� ��Ű�� ��ġ
	```bash
	dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
	dotnet add package System.IdentityModel.Tokens.Jwt
	```

	5. application.json ���Ͽ� JWT ���� �߰�
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
		"Issuer": "https://localhost:7000", // ��ū�� �����ϴ� ������ �ּ� (���� �ۿ����� ������ ������)
		"Audience": "https://localhost:7000", // ��ū�� ������ ��� (���� �ۿ����� ������ ������)
		"Secret": "YourSuperStrongAndComplexSecretKeyForJwtAuthenticationThatIsAtLeast32CharactersLong", // ��ū ���� ���� ��� Ű (�ּ� 32�� �̻� ����, �ſ� �߿�!)
		"TokenExpirationMinutes": 60 // ��ū ���� �ð� (��)
	  }
	}
	```
	
	6. Program.cs ���Ͽ� JWT ���� ���� �߰�
	```csharp
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

	// ���� �� ���� �ο� �̵���� ���������ο� �߰� (���� �߿�!)
	app.UseAuthentication(); // <--- ���� �̵����: HTTP ��û���� JWT ��ū�� Ȯ���ϰ� ����� �ſ�(ClaimsPrincipal)�� �����մϴ�.
	app.UseAuthorization();  // <--- ���� �ο� �̵����: ����� ����� �ſ��� ������� ���ҽ� ���� ������ Ȯ���մϴ�.
	```

	7. ��ȣ�� ��������Ʈ�� [Authorize] Ư�� �߰�
	```csharp
	[Authorize] // �� ��������Ʈ�� ������ ����ڸ� ������ �� �ֽ��ϴ�.
	[HttpGet("protected")]
	public IActionResult GetProtectedResource()
	{
		return Ok("This is a protected resource accessible only to authenticated users.");
	}
	```

	8. ��ȣ���� ���� ��������Ʈ�� [AllowAnonymous] Ư�� �߰�
	```csharp
	[AllowAnonymous] // �� ��������Ʈ�� �������� ���� ����ڵ� ������ �� �ֽ��ϴ�.
	[HttpGet("public")]
	public IActionResult GetPublicResource()
	{
		return Ok("This is a public resource accessible to everyone.");
	}
	```

	9. JWT ��ū ���� �� ��ȯ�� ���� ��������Ʈ �߰�
	```csharp
	[AllowAnonymous]
    [HttpGet("GetJwtToken")]
    public IActionResult GetJwtToken()
    {
        var token = GenerateJwtToken("username", "User");
        return Ok(new { Token = token });
    }

    // JWT ��ū�� �����ϴ� private ���� �޼���
	private readonly IConfiguration _configuration; // ����(Configuration) ����

    public WeatherForecastController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    private string GenerateJwtToken(string username, string role)
    {
        // appsettings.json���� JWT ���� ��������
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["Secret"];
        var issuer = jwtSettings["Issuer"];
        var audience = jwtSettings["Audience"];
        var tokenExpirationMinutes = int.Parse(jwtSettings["TokenExpirationMinutes"] ?? "60");

        // ��� Ű�� ����Ʈ �迭�� ��ȯ�Ͽ� ���� Ű ����
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!)); // secretKey�� null�� �ƴϹǷ� ! ���
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); // HmacSha256 �˰������� ����

        // Ŭ����(Claims): ��ū�� ���Ե� ����� ���� (����� �̸�, ���� ��)
        // �� ������ ���߿� HttpContext.User.Claims�� ���� ������ �� �ֽ��ϴ�.
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),       // Subject (��ū�� ��ü, ����� ���� �ĺ���)
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID (��ū�� ���� �ĺ���)
            new Claim(ClaimTypes.Name, username),                   // ����� �̸� Ŭ����
        };

        // ���� Ŭ���� �߰�
        if (!string.IsNullOrEmpty(role))
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        // JWT ��ū ����
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(tokenExpirationMinutes), // ��ū ���� �ð� ����
            signingCredentials: credentials);

        // ��ū�� ���ڿ��� ����ȭ�Ͽ� ��ȯ
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
	```