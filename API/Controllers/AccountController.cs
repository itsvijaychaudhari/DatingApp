using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _dataContext;
        private readonly ITokenServices _service;
        public AccountController(DataContext dataContext, ITokenServices service)
        {
            _service = service;
            _dataContext = dataContext;

        }
        [HttpPost("Register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            using var hmac = new HMACSHA512();

            if (await UserNameExists(registerDto.userName)) return BadRequest("UserName is taken");


            var user = new AppUser()
            {
                Name = registerDto.userName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
                PasswordSalt = hmac.Key
            };
            _dataContext.User.Add(user);
            await _dataContext.SaveChangesAsync();

            return new UserDto()
            {
                Username = registerDto.userName,
                Token = _service.CreateToken(user)
            };
        }
        [HttpPost("Login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _dataContext.User.SingleOrDefaultAsync(x => x.Name == loginDto.Username);
            if (user == null) return BadRequest("Invalid Username");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return BadRequest("Invalid password");
            }
            return new UserDto (){
                Username = loginDto.Username,
                Token = _service.CreateToken(user)
            };
        }

        private async Task<bool> UserNameExists(string userName)
        {
            return await _dataContext.User.AnyAsync(x => x.Name == userName.ToLower());
        }

    }
}