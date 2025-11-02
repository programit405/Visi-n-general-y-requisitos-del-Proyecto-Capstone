using System.Text.RegularExpressions;
using System.Web;

namespace security_and_authentication.Helpers
{
    public static class InputValidationHelper
    {
        // SQL Injection patterns to detect
        private static readonly string[] SqlInjectionPatterns = new[]
        {
            @"(\bOR\b|\bAND\b)\s+[\w\s]*=",
            @"(;|\-\-|\/\*|\*\/)",
            @"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b|\bEXEC\b|\bEXECUTE\b)",
            @"(\bxp_\b|\bsp_\b)",
            @"('|""|`)",
            @"(\\x[0-9a-fA-F]{2})",
            @"(%27|%22)",
            @"(\bCAST\b|\bCONVERT\b|\bDECLARE\b)"
        };

        // XSS patterns to detect
        private static readonly string[] XssPatterns = new[]
        {
            @"<script[^>]*>.*?</script>",
            @"javascript:",
            @"on\w+\s*=",
            @"<iframe[^>]*>",
            @"<object[^>]*>",
            @"<embed[^>]*>",
            @"<img[^>]*>",
            @"<svg[^>]*>",
            @"<link[^>]*>",
            @"<style[^>]*>",
            @"eval\s*\(",
            @"expression\s*\(",
            @"vbscript:",
            @"data:text/html"
        };

        /// <summary>
        /// Validates input for SQL injection attempts
        /// </summary>
        public static bool ContainsSqlInjection(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            foreach (var pattern in SqlInjectionPatterns)
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Validates input for XSS attempts
        /// </summary>
        public static bool ContainsXss(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            foreach (var pattern in XssPatterns)
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Comprehensive validation for both SQL injection and XSS
        /// </summary>
        public static (bool IsValid, string ErrorMessage) ValidateInput(string input, string fieldName = "Input")
        {
            if (string.IsNullOrWhiteSpace(input))
                return (true, string.Empty);

            if (ContainsSqlInjection(input))
                return (false, $"{fieldName} contains potentially malicious SQL patterns.");

            if (ContainsXss(input))
                return (false, $"{fieldName} contains potentially malicious script patterns.");

            return (true, string.Empty);
        }

        /// <summary>
        /// Sanitize input by encoding HTML special characters
        /// </summary>
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return input;

            // HTML encode to prevent XSS
            return HttpUtility.HtmlEncode(input);
        }

        /// <summary>
        /// Validates email format
        /// </summary>
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            try
            {
                var pattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
                return Regex.IsMatch(email, pattern, RegexOptions.IgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates that input contains only alphanumeric characters and allowed special chars
        /// </summary>
        public static bool IsAlphanumericWithSpecialChars(string input, string allowedSpecialChars = "")
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            var pattern = $@"^[a-zA-Z0-9{Regex.Escape(allowedSpecialChars)}]+$";
            return Regex.IsMatch(input, pattern);
        }

        /// <summary>
        /// Validates input length
        /// </summary>
        public static bool IsValidLength(string input, int minLength = 0, int maxLength = int.MaxValue)
        {
            if (string.IsNullOrEmpty(input))
                return minLength == 0;

            return input.Length >= minLength && input.Length <= maxLength;
        }

        /// <summary>
        /// Comprehensive validation for login credentials
        /// </summary>
        public static (bool IsValid, List<string> Errors) ValidateLoginInput(string email, string password)
        {
            var errors = new List<string>();

            // Validate email
            if (string.IsNullOrWhiteSpace(email))
            {
                errors.Add("Email is required.");
            }
            else
            {
                if (!IsValidEmail(email))
                    errors.Add("Invalid email format.");

                var emailValidation = ValidateInput(email, "Email");
                if (!emailValidation.IsValid)
                    errors.Add(emailValidation.ErrorMessage);

                if (!IsValidLength(email, 3, 254))
                    errors.Add("Email must be between 3 and 254 characters.");
            }

            // Validate password
            if (string.IsNullOrWhiteSpace(password))
            {
                errors.Add("Password is required.");
            }
            else
            {
                var passwordValidation = ValidateInput(password, "Password");
                if (!passwordValidation.IsValid)
                    errors.Add(passwordValidation.ErrorMessage);

                if (!IsValidLength(password, 6, 100))
                    errors.Add("Password must be between 6 and 100 characters.");
            }

            return (errors.Count == 0, errors);
        }

        /// <summary>
        /// Validates registration input
        /// </summary>
        public static (bool IsValid, List<string> Errors) ValidateRegistrationInput(string email, string password)
        {
            return ValidateLoginInput(email, password);
        }

        /// <summary>
        /// Validates generic string input with customizable rules
        /// </summary>
        public static (bool IsValid, List<string> Errors) ValidateStringInput(
            string input,
            string fieldName,
            bool required = true,
            int minLength = 0,
            int maxLength = int.MaxValue,
            bool checkSqlInjection = true,
            bool checkXss = true)
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(input))
            {
                if (required)
                    errors.Add($"{fieldName} is required.");
                return (errors.Count == 0, errors);
            }

            if (!IsValidLength(input, minLength, maxLength))
                errors.Add($"{fieldName} must be between {minLength} and {maxLength} characters.");

            if (checkSqlInjection && ContainsSqlInjection(input))
                errors.Add($"{fieldName} contains potentially malicious SQL patterns.");

            if (checkXss && ContainsXss(input))
                errors.Add($"{fieldName} contains potentially malicious script patterns.");

            return (errors.Count == 0, errors);
        }
    }
}
