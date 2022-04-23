using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Kerry_Test.Controllers
{
    [Route("api")]
    [ApiController]
    public class APIController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public APIController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        //POST/api/register
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRegister request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.Fullname = request.Fullname;
            user.Username = request.Username;
            user.PasswordSalt = passwordSalt;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }

        //POST/api/login
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserLogin request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password.");
            }
            string token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1));

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passowrdSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passowrdSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        //GET/api/books
        [HttpGet("books")]
        public async Task<ActionResult> ViewData()
        {
            try
            {
                if(user.Username != string.Empty)
                {
                    string url = "https://api.itbook.store/1.0/search/mysql";
                    var client = new HttpClient();
                    GetDefaultRequestHeaders(client).Add("accept_token", "");
                    var response = await client.GetAsync(url);
                    var resultContent = await response.Content.ReadAsStringAsync();
                    JObject jsonResponse = JObject.Parse(resultContent);
                    var list = JsonConvert.DeserializeObject<List<BookModel>>(jsonResponse["books"].ToString());
                    return Ok(list);
                }
                else
                {
                    return BadRequest("Please login.");
                }
            }
            catch
            {
                return BadRequest("Load data error.");
            }
        }

        private static HttpRequestHeaders GetDefaultRequestHeaders(HttpClient client)
        {
            return client.DefaultRequestHeaders;
        }
    }
}
