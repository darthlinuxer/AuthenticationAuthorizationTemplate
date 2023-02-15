using System.ComponentModel.DataAnnotations;

namespace AAA.API.Models;

public record UserRecordDTO
{
    [Required]
    public string UserName { get; set; }
    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    public string? Audience { get; set; }
    public string? Role { get; set; }
    public string? SecurityLevel {get; set;}
}