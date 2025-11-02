using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using security_and_authentication.Helpers;

public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        //app.MapGet("/login", () => Results.Ok("Login endpoint - implement login logic here"));


        app.MapPost("/api/create-role", async (RoleManager<IdentityRole> roleManager, RoleDTO model) =>
       {

           // Validate the model data
           var validationContext = new ValidationContext(model);
           var validationResults = new List<ValidationResult>();
           if (!Validator.TryValidateObject(model, validationContext, validationResults, true))
           {
               var errors = validationResults.Select(e => e.ErrorMessage);
               return Results.BadRequest(errors);
           }

           if (!await roleManager.RoleExistsAsync(model.RoleName))
           {
               // Create a new role and save to the database
               var role = new IdentityRole { Name = model.RoleName, NormalizedName = model.RoleName.ToUpper() };
               var result = await roleManager.CreateAsync(role);

               if (!result.Succeeded)
               {
                   return Results.BadRequest(result.Errors);
               }

           }
           return Results.Ok("Role created successfully");
       });


        app.MapGet("/api/get-role", async (RoleManager<IdentityRole> roleManager) =>
        {
            var role = new IdentityRole { Name = "Admin" };
            var result = await roleManager.GetRoleIdAsync(role);
            if (result == null)
            {
                return Results.BadRequest("Invalid Role");
            }
            return Results.Ok(result);
        });


        app.MapPost("/api/register", async (UserManager<IdentityUser> userManager, RegisterViewModel model) =>
        {

            // Validate the model data
            var validationContext = new ValidationContext(model);
            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(model, validationContext, validationResults, true))
            {
                var errors = validationResults.Select(e => e.ErrorMessage);
                return Results.BadRequest(errors);
            }

            // Validate input for SQL injection and XSS
            var validation = InputValidationHelper.ValidateRegistrationInput(model.Email, model.Password);
            if (!validation.IsValid)
            {
                return Results.BadRequest(new { errors = validation.Errors });
            }

            // Create a new user and save to the database
            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return Results.BadRequest(result.Errors);
            }

            return Results.Ok("User registered successfully");
        });


        // New endpoint for registration with email confirmation

        app.MapPost("/api/register-with-email-confirmation", async (
    RegisterViewModel model,
    UserManager<IdentityUser> userManager,
    IEmailSender emailSender,
    LinkGenerator linkGenerator,
    HttpContext httpContext) =>
{
    var user = new IdentityUser { UserName = model.Email, Email = model.Email };
    var result = await userManager.CreateAsync(user, model.Password);

    if (!result.Succeeded)
    {
        return Results.BadRequest(result.Errors);
    }

    var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
    var encodedToken = WebUtility.UrlEncode(token);

    var confirmationUrl = linkGenerator.GetUriByName(
        httpContext,
        "confirm-email",
        new { userId = user.Id, token = encodedToken }
    );

    var emailBody = $"Please confirm your email by clicking this link: <a href='{confirmationUrl}'>Confirm Email</a>";

    await emailSender.SendEmailAsync(model.Email, "Confirm your email", emailBody);

    return Results.Ok("Registration successful. Please check your email to confirm your account.");
});

        app.MapPost("/api/assign-role", async (UserManager<IdentityUser> userManager, AssignRoleDTO model) =>
        {

            // Validate the model data
            var validationContext = new ValidationContext(model);
            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(model, validationContext, validationResults, true))
            {
                var errors = validationResults.Select(e => e.ErrorMessage);
                return Results.BadRequest(errors);
            }

            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Results.NotFound("User not found.");
            }

            var result = await userManager.AddToRoleAsync(user, model.Role);

            if (!result.Succeeded)
            {
                return Results.BadRequest(result.Errors);
            }

            return Results.Ok("User Role Assign successfully");
        });
        app.MapPost("/api/add-claim", async (UserManager<IdentityUser> userManager, AddClaimDTO model) =>
        {

            // Validate the model data
            var validationContext = new ValidationContext(model);
            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(model, validationContext, validationResults, true))
            {
                var errors = validationResults.Select(e => e.ErrorMessage);
                return Results.BadRequest(errors);
            }

            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Results.NotFound("User not found.");
            }

            var result = await userManager.AddClaimAsync(user, new Claim(model.ClaimName, model.ClaimValue));

            if (!result.Succeeded)
            {
                return Results.BadRequest(result.Errors);
            }

            return Results.Ok("User claim added successfully");
        });
        app.MapPost("/api/add-claim-to-role", async (RoleManager<IdentityRole> roleManager, AddClaimRoleDTO model) =>
        {

            // Validate the model data
            var validationContext = new ValidationContext(model);
            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(model, validationContext, validationResults, true))
            {
                var errors = validationResults.Select(e => e.ErrorMessage);
                return Results.BadRequest(errors);
            }

            var role = await roleManager.FindByNameAsync(model.RoleName);
            if (role == null)
            {
                return Results.NotFound("Role not found.");
            }

            var result = await roleManager.AddClaimAsync(role, new Claim(model.ClaimName, model.ClaimValue));

            if (!result.Succeeded)
            {
                return Results.BadRequest(result.Errors);
            }

            return Results.Ok("Role claim added successfully");
        });


        app.MapGet("/api/confirm-email", async (UserManager<IdentityUser> userManager, string userId, string token) =>
        {
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return Results.BadRequest("Invalid User ID");
            }

            var result = await userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return Results.Ok("Email confirmed successfully");
            }
            else
            {
                return Results.BadRequest("Error confirming email");
            }
        });



        app.MapPost("/api/login", async (
                                LoginViewModel model,
                                SignInManager<IdentityUser> signInManager,
                                UserManager<IdentityUser> userManager) =>
            {

                // Validate input for SQL injection and XSS
                var validation = InputValidationHelper.ValidateLoginInput(model.Email, model.Password);
                if (!validation.IsValid)
                {
                    return Results.BadRequest(new { errors = validation.Errors });
                }


                var user = await userManager.FindByEmailAsync(model.Email);
                if (user == null)
                    return Results.BadRequest("Invalid login attempt.");

                await signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: false);

                return Results.Ok("Logged in successfully.");
            });



        app.MapPost("/api/logout", async (SignInManager<IdentityUser> signInManager) =>
            {

                await signInManager.SignOutAsync();

                return Results.Ok("Log out successfully.");
            });
    }


}