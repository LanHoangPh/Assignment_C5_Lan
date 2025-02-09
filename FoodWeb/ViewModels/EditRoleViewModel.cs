using System.ComponentModel.DataAnnotations;

namespace FoodWeb.ViewModels
{
    public class EditRoleViewModel
    {
        [Required]
        public string Id { get; set; }

        [Required(ErrorMessage = "Role Không được bỏ trống ")]
        public string RoleName { get; set; }
    }
}
