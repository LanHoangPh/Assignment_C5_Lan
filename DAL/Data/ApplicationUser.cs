using DAL.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DAL.Data
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string FullName { get; set; }
        // Mối quan hệ 1 - 1 với Cart
        public virtual Cart? Cart { get; set; }
        // Mối quan hệ  1 - n với Order
        public virtual ICollection<Order>? Order { get; set; } = new List<Order>();
    }
}
