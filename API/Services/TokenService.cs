using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenServices
    {
        public readonly SymmetricSecurityKey _key;

        public TokenService(IConfiguration iConfig )
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(iConfig["TokenKey"]));
        }
        public string CreateToken(AppUser user)
        {
            var claim = new List<Claim>{
                new Claim(JwtRegisteredClaimNames.NameId, user.Name)
            };

            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256Signature);
            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claim),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials  = creds
            }; 
            var tokenHandler =  new JwtSecurityTokenHandler();

            var token  = tokenHandler.CreateToken(tokenDescription);
            return tokenHandler.WriteToken(token);
        }
    }
}