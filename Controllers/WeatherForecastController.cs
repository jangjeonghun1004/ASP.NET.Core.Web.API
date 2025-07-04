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
        private readonly IConfiguration _configuration; // 구성(Configuration) 주입

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

        // JWT 토큰을 생성하는 private 헬퍼 메서드
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
    }
}
