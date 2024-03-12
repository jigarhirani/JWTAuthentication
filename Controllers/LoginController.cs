using JWTAuthentication.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        #region Config
        private IConfiguration Configuration;
        public LoginController(IConfiguration _configuration)
        {
            Configuration = _configuration;
        }
        #endregion

        #region Generate Token(Preparation)
        private string GenerateToken()
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(Configuration["Jwt:Issuer"], Configuration["Jwt:Audience"], null,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        #endregion

        #region Authentication Using Static Data
        [AllowAnonymous]
        [HttpPost("LoginStatic")]
        public IActionResult LoginStatic(Users users)
        {
            IActionResult response = Unauthorized();
            if (users.UserName == "admin" && users.Password == "1234")
            {
                var token = GenerateToken();
                response = Ok(new { token = token });
            }
            return response;
        }
        #endregion                

        #region Login Using Database
        [AllowAnonymous]
        [HttpPost("LoginDatabase")]
        public IActionResult Login([FromBody] Users users)
        {

            if (ModelState.IsValid)
            {
                SqlConnection conn = new SqlConnection(Configuration.GetConnectionString("MyConnection"));
                conn.Open();
                SqlCommand objCmd = conn.CreateCommand();
                objCmd.CommandType = CommandType.StoredProcedure;
                objCmd.CommandText = "PR_SEC_User_Login";
                objCmd.Parameters.AddWithValue("@UserName", users.UserName);
                objCmd.Parameters.AddWithValue("@Password", users.Password);
                SqlDataReader objSDR = objCmd.ExecuteReader();
                DataTable dtLogin = new DataTable();

                Dictionary<string, dynamic> data = new Dictionary<string, dynamic>();
                Dictionary<string, dynamic> response = new Dictionary<string, dynamic>();

                // Check if Data Reader has Rows or not
                // if row(s) does not exists that means either username or password or both are invalid.
                if (!objSDR.HasRows)
                {
                    response.Add("status", "Invalid Credentials");
                    response.Add("token", null);
                    response.Add("data", null);
                }
                else
                {
                    dtLogin.Load(objSDR);

                    //Load the retrived data to session through HttpContext.
                    foreach (DataRow dr in dtLogin.Rows)
                    {
                        data.Add("UserID", dr["UserID"].ToString());
                        data.Add("UserName", dr["UserName"].ToString());
                        data.Add("MobileNo", dr["MobileNo"].ToString());
                        data.Add("Email", dr["Email"].ToString());
                    }
                    //Prepare Token 
                    var token = GenerateToken();

                    response.Add("status", "success");
                    response.Add("token", token);
                    response.Add("data", data);
                }
                return Ok(response);
            }
            else
            {
                return BadRequest();
            }
        }
        #endregion        
    }
}
