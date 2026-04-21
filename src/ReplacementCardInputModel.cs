using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace SecureFileUpload.Models
{
    /// <summary>
    /// Model for Replacement Card forms (Library and Remote)
    /// </summary>
    public class ReplacementCardInputModel
    {
        // ==========================================
        // CONTEXT & FORM TYPE
        // ==========================================

        public string? Context { get; set; }
        public string? form_type { get; set; }

        // ==========================================
        // PATRON NAME
        // ==========================================

        [Required(ErrorMessage = "First name is required.")]
        [StringLength(255)]
        [Display(Name = "First Name")]
        public string patron_firstName { get; set; } = string.Empty;

        [StringLength(255)]
        [Display(Name = "Middle Name")]
        public string? patron_middleName { get; set; }

        [Required(ErrorMessage = "Last name is required.")]
        [StringLength(255)]
        [Display(Name = "Last Name")]
        public string patron_lastName { get; set; } = string.Empty;

        // ==========================================
        // BIRTH DATE
        // ==========================================

        [Required(ErrorMessage = "Birth date is required.")]
        [Display(Name = "Birth Date")]
        public string formattedBirthDate { get; set; } = string.Empty;

        // ==========================================
        // NEW PIN
        // ==========================================

        [Required(ErrorMessage = "PIN is required.")]
        [StringLength(4, MinimumLength = 4, ErrorMessage = "PIN must be exactly 4 digits.")]
        [RegularExpression(@"^\d{4}$", ErrorMessage = "PIN must be exactly 4 digits.")]
        [Display(Name = "New 4-Digit PIN")]
        public string patron_pin { get; set; } = string.Empty;

        // ==========================================
        // CONTACT INFORMATION
        // ==========================================

        [Required(ErrorMessage = "Email address is required.")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
        [StringLength(255)]
        [Display(Name = "Email Address")]
        public string patronAddress_emailAddress { get; set; } = string.Empty;

        [Required(ErrorMessage = "Phone number is required.")]
        [StringLength(12)]
        [Display(Name = "Phone Number")]
        public string? phone { get; set; }

        public string? formatted_phone { get; set; }

        // ==========================================
        // MAILING ADDRESS
        // ==========================================

        [Required(ErrorMessage = "Street address is required.")]
        [StringLength(255)]
        [Display(Name = "Street Address")]
        public string? patronAddress_street { get; set; }

        [StringLength(50)]
        [Display(Name = "Apt/Unit #")]
        public string? patronAddress_apartment { get; set; }

        [Required(ErrorMessage = "City is required.")]
        [StringLength(255)]
        [Display(Name = "City")]
        public string? patronAddress_city { get; set; }

        [Required(ErrorMessage = "State is required.")]
        [StringLength(2)]
        [Display(Name = "State")]
        public string? patronAddress_state { get; set; } = "FL";

        [Required(ErrorMessage = "ZIP code is required.")]
        [StringLength(10)]
        [RegularExpression(@"^\d{5}(-\d{4})?$", ErrorMessage = "Please enter a valid ZIP code.")]
        [Display(Name = "ZIP Code")]
        public string? patronAddress_postalCode { get; set; }

        // ==========================================
        // LIBRARY SELECTION
        // ==========================================

        [Required(ErrorMessage = "Please select a home library.")]
        [Display(Name = "Preferred Home Library")]
        public string? library { get; set; }

        // ==========================================
        // LIBRARY NEWS
        // ==========================================

        public string user_cat_7 { get; set; } = "YESNEWS";

        // ==========================================
        // NOTIFICATIONS / SMS
        // ==========================================

        public string? notify_via { get; set; } = "Email";
        public string? sms_phone { get; set; }
        public string? sms_country { get; set; } = "US";
        public bool sms_bill { get; set; }
        public bool sms_overdue { get; set; }
        public bool sms_pickup { get; set; }
        public bool sms_message { get; set; }
        public bool sms_announce { get; set; }

        // ==========================================
        // DRIVER'S LICENSE / ID
        // ==========================================

        [Required(ErrorMessage = "Driver's License or ID number is required.")]
        [StringLength(255)]
        [Display(Name = "Driver's License or State ID Number")]
        public string? dl_number { get; set; }

        // ==========================================
        // FILE UPLOADS
        // Bound from multipart/form-data input name="uploadedFiles"
        // ==========================================
        public List<IFormFile>? uploadedFiles { get; set; }

        // ==========================================
        // LEGACY ALIASES (for backward compatibility)
        // ==========================================

        public string? address1
        {
            get => patronAddress_street;
            set => patronAddress_street = value;
        }

        public string? address2
        {
            get => patronAddress_apartment;
            set => patronAddress_apartment = value;
        }

        public string? city
        {
            get => patronAddress_city;
            set => patronAddress_city = value;
        }

        public string? state
        {
            get => patronAddress_state;
            set => patronAddress_state = value;
        }

        public string? zip
        {
            get => patronAddress_postalCode;
            set => patronAddress_postalCode = value;
        }
    }
}
