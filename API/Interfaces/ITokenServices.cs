using API.Entities;

namespace API.Interfaces
{
    public interface ITokenServices
    {
        public string CreateToken(AppUser user);
    }
}