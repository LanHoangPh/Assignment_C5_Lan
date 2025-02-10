using Microsoft.AspNetCore.Mvc;

namespace FoodWeb.Controllers
{
    public class CustomerController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
