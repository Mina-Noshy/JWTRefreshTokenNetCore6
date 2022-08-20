using System.ComponentModel.DataAnnotations;

namespace WebAppService.ViewModels.Auth
{
    public class TokenRequestVM
    {
        [EmailAddress]
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
