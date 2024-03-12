using JWTAuthentication.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmployeeController : ControllerBase
    {
        #region GetDetails (TO Test Without JWT Authentication)
        [HttpGet]
        [Route("GetDetailsWithoutJwt")]
        public string GetDetails()
        {
            return "Authenticated Without JWT";
        }
        #endregion

        #region GetData (To Test JWT Authentication)
        [Authorize]
        [HttpGet]
        [Route("GetData")]
        public string GetData()
        {
            return "Authenticated with JWT";
        }
        #endregion        

        #region PostUser (To AddUser With JWT Authentication)
        [Authorize]
        [HttpPost("AddEmployee")]
        public string AddUser(Users users)
        {
            return "User Added With Username " + users.UserName;
        }
        #endregion
    }
}
