using System.ComponentModel.DataAnnotations;

namespace FoodWeb.ViewModels
{
    public class CreateRoleViewModel
    {
        [Required(ErrorMessage = "Role Không được bỏ trống ")]
        [Display(Name = "Role")]
        public string RoleName { get; set; }
    }
}
