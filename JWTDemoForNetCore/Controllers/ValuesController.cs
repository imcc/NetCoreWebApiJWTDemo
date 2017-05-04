using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NLog;

namespace JWTDemoForNetCore.Controllers
{
    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        // GET api/values
        [HttpGet]
        public IEnumerable<string> Get()
        {
            var claims = HttpContext.User.Claims.ToList();
            var userId = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;

            _logger.Info($"当前用户：{userId}/{HttpContext.User.Identity.Name}");

            foreach (var claim in claims)
            {
                _logger.Info($"{claim.Type}:{claim.Value}");
            }
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        [HttpGet("{id}")]
        [Authorize(Roles = "Admin")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
