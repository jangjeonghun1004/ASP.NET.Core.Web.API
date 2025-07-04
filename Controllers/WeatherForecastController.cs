using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ASP.NET.Core.Web.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };
        private readonly ILogger<WeatherForecastController> _logger;
        private readonly IConfiguration _configuration; // ����(Configuration) ����

        public WeatherForecastController(ILogger<WeatherForecastController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [Authorize]
        [HttpGet("NeedJwtToken")]
        public IEnumerable<WeatherForecast> NeedJwtToken()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [AllowAnonymous]
        [HttpGet("GetJwtToken")]
        public IActionResult GetJwtToken()
        {
            var token = GenerateJwtToken("username", "User");
            return Ok(new { Token = token });
        }

        // JWT ��ū�� �����ϴ� private ���� �޼���
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
    }
}
