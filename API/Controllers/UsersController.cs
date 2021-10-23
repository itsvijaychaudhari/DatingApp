using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class UsersController : BaseApiController
    {
        private readonly DataContext _dataContext;
        public UsersController(DataContext dataContext)
        {
            _dataContext = dataContext;
        }

        [HttpGet]
        public  async Task<ActionResult<IEnumerable<AppUser>>> GetUsers()
        {
            return await _dataContext.User.ToListAsync();
        } 
        [Authorize]
        [HttpGet("id")]
        public async Task<ActionResult<AppUser>> GetUser(int id)
        {
            return await _dataContext.User.FindAsync(id);
        }

    }
}