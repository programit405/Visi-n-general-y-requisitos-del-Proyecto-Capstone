# Securing APIs With ASP.NET Identity

### **Introduction:**
Welcome to Securing APIs with ASP.NET Identity. In this module, you'll learn to secure your applications with user roles, claims, token-based authentication, and external authentication providers. By the end, you'll be ready to build secure, reliable systems that protect users and data. We will begin by exploring ASP.NET Identity and understanding its role in managing authentication and authorization for modern applications. Next, we'll examine user registration and authentication, and learn how to implement secure and efficient workflows for user access. Then, we'll focus on managing user roles and claims, a crucial step in defining and controlling access within your applications. 

### **ASP.NET Identity:**

#### **ASP.NET Identity** is a membership system designed to handle user authentication, authorization, and user roles in secure *ASP.NET* applications. Its features ensure a robust framework for managing identity-related tasks efficiently.

### **Key Features and Functionalities**

#### *User Authentication:*
- Validates user identity before granting access.

- Supports multi-factor authentication (MFA), password recovery, and email confirmation for enhanced security.
  
#### *Authorization and Role Management*
- Uses authorization ("AuthZ") to define what authenticated users can do based on roles or permissions.
  
- Roles group permissions for easier management (e.g., "Admin" vs. "User").

#### *Integration and Modularity*
- Integrates with ASP.NET Core and allows OAuth 2.0 support for external login providers like Google or Facebook.

### **Authentication & Authorization**

***Authentication (AuthN):***
- Authentication verifies users' identities before granting them access to a system or application.
  
***Example:*** *Consider when you log into a website, you enter your username and password. The system then checks if the information matches an existing account to verify it's really you. Authentication confirms your identity and ensures that only authorized users can access your personal data or secure features within the application.Once the system has identified the user through authentication, it needs to decide what actions they are allowed to take. This is where authorization comes in.*

***Authorization (AuthZ):***
- Authorization controls what a user can do once they're authenticated. In other words, it controls their access based on their role or permissions

***Example:*** *In a workplace application, an employee might only be able to review their personal information, but a manager can approve time off requests for the entire team.* 

***Role Management:***
- Instead of assigning permissions to each user individually, roles allow you to group users within the same permissions, simplifying management. User roles are a predefined set of permissions assigned to groups of users. Instead of giving permissions individually, you assign them to roles.

***Example:*** *Imagine an online store where merchants can add products to the inventory while customers can browse and make purchases. Each role has different capabilities.*


***Multi-factor authentication (MFA):***
- which adds an extra layer of security by requiring your password plus another step, like entering a code sent to your device.


### **Architecture of ASP.NET Identity**

we will explain the key components of ASP.NET Identity and how they work together to manage users, roles, and authentication. Before we explore each component, it's essential to understand that these tools work together to create a complete ecosystem. Each component plays a specific role in managing users and enhancing the application's security.

| Key components of ASP.NET Identity    |
|--------------|
| User Manager |
| Sign-in Manager |
| Role Manager |
| IdentityDbContext |


***User Manager:***
- User Manager processes operations such as creating, deleting, and updating users, setting passwords, and managing user claims. 

***Example:***
Imagine using an app where you can create an account. User Manager makes that possible. It manages creating and updating your profile and removing your account if needed. Since User Manager manages account creation, we also need a way to verify that users are who they claim to be. For this, we use Sign-in Manager.

***Sign-in Manager:***
- Sign-in Manager is a component in ASP.NET Identity that takes on the responsibility of managing user authentication, processing sign-ins and sign-outs, and ensuring that only users with valid credentials can log in. 

***Example:***
Think of a time when you logged into an app with your password and username. Sign-in Manager is the part of the system that checks your credentials and securely signs you in.

***Role Manager:***
- Role Manager helps define what different users can do within the application by creating roles and assigning users to them. Role Manager can assign the admin role to some users so they can manage the system, while others are given roles that allow them to only access certain features. 

***Example:***
In a company's internal system, you don't want every employee to have the same permissions. 
Admins should manage sensitive data, while regular employees can only access certain information. Role Manager makes this possible. 


***IdentityDbContext:***
- IdentityDB Context manages the secure storage of information related to users, roles, and claims. IdentityDB Context connects an application to a database, securely storing and retrieving user details, roles, claims, and permissions. 


***Example:***
IdentityDB Context stores information like user credentials or access level in a secure database for future use. This setup ensures that user data remains available for future logins.

### For using ASP.NET Identity
Install necessary packages

```
dotnet add package Microsoft.AspNetCore.Identity
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore
```
**Microsoft.AspNetCore.Identity** provides core interfaces and classes for ASP.NET Identity, enabling user authentication and authorization.

**Microsoft.AspNetCore.Identity.EntityFrameworkCore** provides Entity Framework Core implementations for ASP.NET Core Identity, enabling seamless integration with databases. It is a bridge between ASP.NET Identity and Entity Framework Core, allowing you to use EF Core as the data store for user information.

**Microsoft.EntityFrameworkCore** is the core package for Entity Framework Core, an object-relational mapper (ORM) that enables .NET developers to work with databases using .NET objects.

For using in-memory database

```
dotnet add package Microsoft.EntityFrameworkCore.InMemory
```
**Microsoft.EntityFrameworkCore.InMemory** provides an in-memory database provider for Entity Framework Core, useful for testing and development scenarios where a lightweight, non-persistent database is needed.

Configure services in Program.cs

```csharp
builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseInMemoryDatabase("InMemoryDb"));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddDefaultTokenProviders();
```

**IdentityDbContext** is a special DbContext that comes pre-configured with all the ASP.NET Identity tables and entity mappings. It is used to manage identity-related data such as:

- Users

- Roles

- UserClaims

- UserLogins

- RoleClaims

- UserTokens


📋Note: If you need to customize the identity model or add additional properties, you can create your own user and role classes that inherit from the default ASP.NET Identity classes. and then use those classes instead of the default ones when configuring Identity services. and also create a custom DbContext that inherits from `IdentityDbContext<TUser, TRole, TKey>`."


**Register authentication and authorization services**

```
builder.Services.AddAuthentication();
builder.Services.AddAuthorization();
```
`AddAuthentication` and `AddAuthorization` methods register the necessary services for handling authentication and authorization in the application.

**Configure middleware in the HTTP request pipeline**

```
app.UseAuthentication();
app.UseAuthorization();
```

Using authentication and authorization middleware is crucial for securing your ASP.NET Core application. These middleware components ensure that users are properly authenticated and authorized to access specific resources or perform certain actions within the application.

When setting up the middleware, it is essential to include these middleware components in the correct order within the HTTP request pipeline. `app.UseAuthentication()` should be called before `app.UseAuthorization()` to ensure that authentication occurs before any authorization checks are performed.




### **User Registration Process**

***User Registration:***
When a new user wants to create an account, the registration process involves several steps to ensure security and proper account setup.

ASP.NET Identity handles these processes when a user registers on a website. Here's how it typically works:

- **Form Submission:** The user fills out a registration form with their email, password, and other required information.
- **Password Hashing:** The password is hashed using a secure algorithm before being stored in the database, ensuring that even if the database is compromised, the actual passwords remain protected.
    - **Password hashing** converts a plain text password into a fixed length string of characters or hash using an algorithm, making it secure and difficult to reverse engineer. 
- **Email Confirmation:** A confirmation email is sent to the user to confirm that the email provided is valid and belongs to them. At this point, the system sends a confirmation email to ensure that the account is genuinely theirs. You may recognize this step when you receive an email with a Verify Account link. Selecting this link proves that the email is theirs, preventing fake accounts and ensuring that they're the ones who registered.
- **Data Storage:** ASP.NET Identity organizes and stores information like your hashed password and email confirmation status in a secure database, ensuring security of your account.

**Create DTO:**

```c#

using System.ComponentModel.DataAnnotations;

public class RegisterViewModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; }

    [Required(ErrorMessage = "Confirm Password is required")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; }
}

```
**Map Endpoint:**
```c#
 app.MapPost("/register", async (UserManager<IdentityUser> userManager, RegisterViewModel model) =>
        {

            // Validate the model data
            var validationContext = new ValidationContext(model);
            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(model, validationContext, validationResults, true))
            {
                var errors = validationResults.Select(e => e.ErrorMessage);
                return Results.BadRequest(errors);
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

```

### **User Authentication Process**


- **Credential submission:** Credential submission is where users enter their username and password into a login form. When submitted, the server receives these details for verification. 

***Example:*** you submit your credentials each time you enter your email and password to log in. Once your credentials have been submitted, the server moves to the next step, password verification. 


- **Password verification:** When a user submits a password, the server hashes it and verifies it against the hash stored in the database. Once a password is verified, the next step is session creation.

- **Session & Cookie creation:**
    - ***Session :*** *A session is a temporary state that securely maintains users' logged in status during their visit to a website*
        
        ***Example:*** *A session keeps you logged in as you explore different parts of a website. Without it, the site would forget you after each section, making browsing difficult. Sessions last for a set time and may expire if inactive, meaning you'll need to log in again.*
    
    Sometimes, users want to stay logged in even after closing their browser. This is where cookies come into play, typically via a Remember Me option.

    - ***Cookie :***  *A cookie is a small piece of data in a website saved in your browser to remember configurations between sessions. When enabled, cookies save login information on your device, letting you stay logged in across multiple visits. Unlike sessions, cookies persist on your device, so you don't have to log in each time you return to the site.*  

    ***Note: Web APIs are typically RESTful (stateless), meaning each request should be independent and contain all necessary information (e.g., tokens in headers). This avoids server-side session tracking.Unlike MVC or Razor Pages, Web API templates don’t include session or cookie.We will discuss later...*** 

- **Role-based Access(RBAC):**  *Role-based access control, or RBAC, is a control mechanism that restricts system access to authorized users based on their roles within an organization. RBAC assigns different roles to users within a system. This role determines what parts of an application they can access.The class RoleManager manages creating and assigning roles to users* 

    ***Example:*** Consider a school computer system. Users might be permitted to update grades, while students can only access their personal records.

    RoleManager makes it easy to create roles like admin, user, or editor and assign them to different users. 

    Register the `RoleManager<IdentityRole>` service in your project:

    ```c#
    builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<IdentityDbContext>();

    ```

- **Claims-based authorization:** *With claims-based authorization in ASP.NET Identity, you gain the flexibility to assign precise access to users based on their unique attributes, creating a more secure and customized experience. Before we discuss claims-based authorization, we must first define what a claim is.* 

    - ***Claims:*** *Claims are name-value pairs that represent an attribute or characteristic of a user or entity.*

        ***Example:*** *Imagine an amusement park that lets people into different areas based on a special wristband. This wristband contains information about you, like your name and age, and what rides you're allowed to go on. These bits of information about you are like claims. For instance, the name-value pair for age could be age and a number value like 22. These are facts about you that the park uses to decide what you can do.*

    Let's now define what claims-based authorization is. Claims-based authorization is a security model where access to resources or applications is determined by evaluating the claims associated with a user's identity. Unlike role-based authentication, RBAC, which relies on predefined roles, claims-based authorization offers more flexibility by allowing permissions based on multiple attributes.

    Claims are assigned using the UserManager class in ASP.NET Identity. Assigning claims is important because it allows us to specify what level of access a user should be assigned. For example, we could assign a claim to a user named Alex, who works in the IT department. You could assign Alex a claim like `department:'IT'`. Doing this would allow Alex to access IT-related resources in an app, like the IT support dashboard, which is available only to IT staff. 
    
    Once claims are assigned, we need to understand how the system is storing claims in a database. In ASP.NET Identity, claims are stored in the database in the ASP.NET User Claims table. 

    ***Example:*** *In our example, when Alex logs in after logging in, the system retrieves Alex's claims directly from the ASP.NET User Claims table. As this claim is stored, Alex can continue accessing IT resources seamlessly without needing to request permissions again. Storing claims in the database ensures that permissions persist across logins, providing a smooth experience for users. This approach makes the app faster and more efficient, even when working with a large number of users. It also maintains consistency and security, especially in distributed systems running on multiple servers. Additionally, it simplifies permission updates. Changes are applied instantly during the next authentication, requiring no extra effort.*

    ***we need to examine how authorization policies are used to control claims in specific system areas?*** 
    
    *Authorization policies are rules that help us decide who can access certain areas of a system. In ASP.NET Identity, these policies check the user's claims before allowing access to a particular area of a system.* 

    ***Comparing Roles and Claims:***
    - *Roles: Predefined and static; ideal for broad access definitions.*
    - *Claims: Dynamic and user-specific, offering more granular and adaptable access management.*



### Secure endpoint creation:


For the `secure endpoint creation`  first thing, I am just going to add basic authorizations here. So I am going to say `RequireAuthorization`. this will require that a user is logged in and has a valid cookie to access this admin route. Here the scure endpoint:

```c#
app.MapGet("/api/admin/dashboard", () => "You are in Admin Dashboard.").RequireAuthorization();
```

```http
GET {{Host_Address}}/api/admin/dashboard
```

Now we are getting a 404 not found. And now that is a bit of a weird behavior here, because we really don't want a 404. 
This is a valid route, but they are unauthorized. And so really what we want to see here is a 401. Now the reason we are seeing a 404 is because the default behavior here is that if a user tries to access a route they are not authenticated to get into, it will try to reroute them to a certain page.

```
📋Note: When use Microsoft Identity, if the try unauthorize access it redirect to login url by default. This is the normal behavior you would want if you were just making a web application or a website. If a user goes to a page that they can't access to, you tell them, hey, go log in. For APIs, this isn't normally the behavior you want. You want them to get an unauthorized. So the issue we're running into with the 404. 
```

We just want to give them a 401. And the way we're going to do that is we're going to go `builder.services.configureApplicationCookie`. And this will take a function that is passed in options. And then we'll say `options.events.onRedirectLogin`. So this event will be called any time that a user is bounced from a route and sent to the login. So when this would happen, we are actually going to sort of overwrite this behavior.

```c#
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        // override unauthorize access redirect path
        if (context.Request.Path.StartsWithSegments("/api") && context.Response.StatusCode == StatusCodes.Status200OK)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
});

```
Let's go ahead create role and create user that we can assign those roles to.
For create an authentication process you need to create role first. we are managing role by `RoleManager`;


**Step-1:** create role endpoint.

```c#
    using System.ComponentModel.DataAnnotations;

    public class RoleDTO
    {
        [Required(ErrorMessage = "Role is required")]
        public string RoleName{ get; set; }

    }

```


```c#

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

           if (! await roleManager.RoleExistsAsync(model.RoleName))
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

```
Here is the api request:

```http
POST {{Host_Address}}/api/create-role
Accept: application/json
Content-Type: application/json

{
    "roleName": "Admin"
}

```


**Step-2:** Assign role to an user

```c#
using System.ComponentModel.DataAnnotations;

public class AssignRoleDTO
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; }

     [Required(ErrorMessage = "Role is required")]
    public string Role{ get; set; }

}
```


```c#
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
        

```
API request:

```http
POST {{Host_Address}}/api/assign-role
Accept: application/json
Content-Type: application/json

{
    "email": "user@example.com",
    "role": "Admin"
}

```




We are completed create role, register an user and also assign role to the targeted user. Next we need to implement login endpoint. Below I will share it: 


**Step-3:** 

```c#
using System.ComponentModel.DataAnnotations;

public class LoginViewModel
{
    [Required(ErrorMessage = "Email is required")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; }
}
```


```c#
     app.MapPost("/api/login", async (
                                LoginViewModel model,
                                SignInManager<IdentityUser> signInManager,
                                UserManager<IdentityUser> userManager) =>
            {
                var user = await userManager.FindByEmailAsync(model.Email);
                if (user == null)
                    return Results.BadRequest("Invalid login attempt.");

                await signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: false);

                return Results.Ok("Logged in successfully.");
            });
        

```
API request:

```http
POST {{Host_Address}}/api/login
Accept: application/json
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "Password123!"
}

```

Let's send a request, create the roles, sign the roles, then log in. Now you can see here, we received this set cookie header. Now this is a special header that your browser will know to then set this cookie with this value. And so this is sort of the secret key that our application is going to send back to say, hey, I'm logged in, this is who I am. And so let's check again here.

API response:

```http
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json; charset=utf-8
Date: Sat, 20 Sep 2025 07:36:58 GMT
Server: Kestrel
Cache-Control: no-cache,no-store
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Pragma: no-cache
Set-Cookie: .AspNetCore.Identity.Application=CfDJ8FSNPT-2TENDt06X1G8-DV_Ikks_E4D9vehehImkhVl1i9yGt0sfwpdj9kJ31DJQsEP8UE9ZpqevpAQZ8CRaMcMno_2FFAJhFShGFmAQ88k6BmBIkxZhQGzLmdQ0GDms-732sPQC3fQ5_k2CRzYnAhPImHTfvxLRBv3CtSYsUOf4a1zZ73aoSXq-8zNSIS7aoRhJbrZv8zLcacxs8qFpCeeFk9QqSKKE4qsfR6xugI7xdjAOBP6_2Y3EnTpAMS9_71BmkZgWrWpOk82HK8L7qnbOjxpfbrdMSvGONjvvCjtBVBHCBVciDLZBJR2VxiqVBLe3NMDLMTlOIZblwjZhgb-p9IpjWW9jAKoPYv6kUVrkAFXdIvh7mCkAItchnz_pt71v2sBjlN2vcuvNz-4iVU7ts4V2mDsOP3c8ffR0xO4RJXhmH69s4Q0p_kIKYL2euxeoXQ5-yzGrF9APmPXaf0vzWMHwhEXGs77iDL7d1qqCimaLk9u7y-7jojDyrtd7p6ZQXQc_LVcMtF3LaA6WyL7WSlmBc3H6ldUz4nbmqhLeH2LTSHZ3F09-MAtoo7K-R8VovA5Up4Y8-hnLajYE7ZoDy2Kdk3qonGxbk0ArPggbkKyVVr36mysmEl9ONTPd-SblR1WDY-pdZYe6rQGJiNfmReNDfn8BhefOwqWU78FLsSYr5pjrBV5tTdi-z5qyhUIv0zf2ohS6iyeIP_5P5QeuTYeyrbaf53li47Wd1xj-aevIPsswluS0_JNp6QJK4n0ur8vfQFhd6jqc4mwPP40LKCGAVYelOB-ELDZAJr1XEsSr5yGbFPDikpbYroVAK-g-v5zELYlO_EddHB4QQBE; path=/; samesite=lax; httponly
Transfer-Encoding: chunked

"Logged in successfully."

```

***Note:*** *Now authorize session is created. copy `Set-Cookie` value and use it to access the secure endpoint*


So the first thing I am going to do is I am just going to add basic authorizations here. So I am going to say `RequireAuthorization`. So this will require that a user is logged in and has a valid cookie to access these two routes. Create a secure endpoint to test our cookie and authentication process by adding . Here the scure endpoint:

```c#
app.MapGet("/api/admin/dashboard", () => "You are in Admin Dashboard.").RequireAuthorization();
```

If I send request to `/api/admin/dashboard`, user claim check, we are unauthorized. So let you do, log in again. And then let's go ahead and grab the cookie. Because what your browser would do normally is grab this cookie and then send it back as the cookie header. And so now if I run this code, we get back a 200 OK admin dashboard.


```http
###

GET {{Host_Address}}/api/admin/dashboard
Cookie: cookie here

```


Now our user has the admin role, but we weren't actually checking for it because we were just checking to see if we had an authorized user by `RequireAuthorization()`. So they just needed to have a cookie that says they had logged in. There was no particular permission required. Look:

```c#
app.MapGet("/api/admin/dashboard", () => "You are in Admin Dashboard.").RequireAuthorization();
```

So now if I change this to say admin, we are now requiring the admin policy, which in this case says that we require the admin role.

```c#
app.MapGet("/api/admin/dashboard", () => "You are in Admin Dashboard.").RequireAuthorization("Admin");
```


Now, goto the rest client and sent request the response will say System.InvalidOperationException: The AuthorizationPolicy named: 'Admin' was not found.

```http
System.InvalidOperationException: The AuthorizationPolicy named: 'Admin' was not found.
   at Microsoft.AspNetCore.Authorization.AuthorizationPolicy.CombineAsync(IAuthorizationPolicyProvider policyProvider, IEnumerable`1 authorizeData, IEnumerable`1 policies)
   at Microsoft.AspNetCore.Authorization.AuthorizationMiddleware.Invoke(HttpContext context)
   at Microsoft.AspNetCore.Authentication.AuthenticationMiddleware.Invoke(HttpContext context)
   at Microsoft.AspNetCore.Diagnostics.DeveloperExceptionPageMiddlewareImpl.Invoke(HttpContext context)

HEADERS
=======
Connection: close
Host: localhost:5033
User-Agent: vscode-restclient
Accept-Encoding: gzip, deflate
Cookie: .AspNetCore.Identity.Application=CfDJ8FSNPT-2TENDt06X1G8-DV-2C4FSJBtOklYqkndQtauiMBa1AZoxhEBRiXp1vNRPbUePWmDrmbWQSq5sRMJER_BxPLImt9laxLezWF7r4t0tlfrRj6QZezKSKIrrhsQ3fJhwgmk4Gs77acBHJT_pN5wGn3pw2KpE4uemQsEdK8ABlOWVG9XOYa0Fio-f9Jona11z1KA0df01I8y_s5kDTyTKcQusHwlNa6tHLOd54Y8KxTPllYXN_4NtwQ3wThOLXZTU2Krkh8_SMMPEsUVzVoTO_Vvr8wASYLsaSpu_CCfyvP0SN19N2c1jfVmn_23DQ3Ch28Acg9icjluSQha8hg98k6YafCyAq7s_UwQBX_1pP-2_93E0oYSJPJ8B2q9VUIhrS-bzdxSHT0clK4VT384CkGDqCFPyjH-EmtLvdfGqGi2ZZINuz-LdDRhHvdoQOMdz2xv4d_D-VcQLN7XHwj5J0ayu8GMGXMd8miTTexishHSpzNZS7cDzFBMZGZCYl_R_ZOn-o4I3Ek7GRpcL7CE5-MJLsPTK9UO4LhohvmMdsqpoefvCJdA2bIMEYJANaUxi78G8hwvOrsqgI7e7EsaQ1ylPrD6htqzXVyIqp1loIu2FnZfpQRCw_G3J3fc69Wwx-L2yvVR6ZqBy2cAjGaiQKsViWvHWSS2wA7Z29oe6YfpZIUH9ymxB0egAqRS7dfzTNUNVTAc2RQ7akCetjFRH3gaoR8TvuWT-2B0b46NIRGnZ9kj4WEuc8S33sLe7jDqM9pULef1uLyneCHnQYdNaU0K5pdnNPoJPOOPLYnwqASnfLi3CHP--Zw6XlDR2dTLL6U5HqovBZVqUY3JS3Ks; path=/; samesite=lax; httponly

```
The AuthorizationPolicy `Admin` was not found. So let's create the policies. So we are going to add our policies on our authorization builder. Now the policy is going to have a name. We'll call this one admin. Now this will take in a policy and this policy requires that the user has an admin role. 

```c#
builder.Services.AddAuthorizationBuilder()
       .AddPolicy("admin", policy => policy.RequireRole("Admin"));
```

So we need to login once again. I will grab this cookie and we will come down and we will replace this cookie with our new cookie. And let's see what we get here, we can acess admin dasboard now.

And we can add more policies to access the apis. like:

```c#
app.MapGet("/api/doctor/dashboard", () => "You are in Doctor Dashboard.").RequireAuthorization("doctor");
app.MapGet("/api/patient/dashboard", () => "You are in Patient Dashboard.").RequireAuthorization("patient");
app.MapGet("/api/user/dashboard", () => "You are in User Dashboard.").RequireAuthorization("user");
```
For achieve it, create new policy like:

```c#
builder.Services.AddAuthorizationBuilder()
       .AddPolicy("admin", policy => policy.RequireRole("Admin"))
       .AddPolicy("doctor", policy => policy.RequireClaim("type", "doctor"))
       .AddPolicy("patient", policy => policy.RequireRole("User").RequireClaim("type", "patient"))
       .AddPolicy("user", policy => policy.RequireRole("User"));
```

Then, we create a add-claim enpoint to add claim to an user:


```c#
using System.ComponentModel.DataAnnotations;

public class AddClaimDTO
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Claim Name is required")]
    public string ClaimName { get; set; }
    
    [Required(ErrorMessage = "Claim Value is required")]
    public string ClaimValue{ get; set; }

}
```


```c#
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

        var result = await userManager.AddClaimAsync(user, new Claim(model.ClaimName,model.ClaimValue));

        if (!result.Succeeded)
        {
            return Results.BadRequest(result.Errors);
        }

        return Results.Ok("User claim added successfully");
    });

```
API request:

```http
POST {{Host_Address}}/api/add-claim
Accept: application/json
Content-Type: application/json

{
    "email": "admin@example.com",
    "claimName": "type",
    "claimValue":"doctor"
}

```

 We added claim to an user successfully. Then, try login and copy the cookie and put it into header. Now, If we try these enpoint now it works as expected.


```http
###

GET {{Host_Address}}/api/admin/dashboard
Cookie: your cookie here


###

GET {{Host_Address}}/api/doctor/dashboard

###

GET {{Host_Address}}/api/patient/dashboard

###
GET {{Host_Address}}/api/user/dashboard


```




### **Conclusion:** 
Here's what we covered in this article. We began by introducing ASP.NET Identity, highlighting its vital role in managing authentication and authorization for modern applications. Next, you explored the process of user registration and authentication, learning how to implement secure workflows that protect user access effectively. Then, we examined how to manage user roles and claims, enabling precise control over application permissions and ensuring robust access management. Congratulations on completing Securing APIs with ASP.NET Identity. You've taken an essential step in building secure, reliable, and user-friendly applications. 







