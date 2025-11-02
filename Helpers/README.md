# Input Validation Helper

## Overview

The `InputValidationHelper` class provides comprehensive input validation to protect against SQL injection and XSS (Cross-Site Scripting) attacks.

## Features

### 1. SQL Injection Detection

Detects common SQL injection patterns including:

- SQL keywords (SELECT, INSERT, UPDATE, DELETE, DROP, etc.)
- SQL operators (OR, AND with conditions)
- SQL comments (--;, /_, _/)
- Stored procedure calls (xp*, sp*)
- Special characters (', ", `)
- URL encoded characters (%27, %22)
- SQL functions (CAST, CONVERT, DECLARE)

### 2. XSS Detection

Detects common XSS attack vectors including:

- Script tags
- JavaScript protocols
- Event handlers (onclick, onload, etc.)
- Malicious HTML tags (iframe, object, embed, img, svg)
- Style tags and expressions
- Eval and expression functions
- VBScript and data URIs

## Usage Examples

### Login Validation

```csharp
var validation = InputValidationHelper.ValidateLoginInput(email, password);
if (!validation.IsValid)
{
    return Results.BadRequest(new { errors = validation.Errors });
}
```

### Registration Validation

```csharp
var validation = InputValidationHelper.ValidateRegistrationInput(email, password);
if (!validation.IsValid)
{
    return Results.BadRequest(new { errors = validation.Errors });
}
```

### Custom String Validation

```csharp
var validation = InputValidationHelper.ValidateStringInput(
    input: userName,
    fieldName: "Username",
    required: true,
    minLength: 3,
    maxLength: 50,
    checkSqlInjection: true,
    checkXss: true
);

if (!validation.IsValid)
{
    return Results.BadRequest(new { errors = validation.Errors });
}
```

### Individual Checks

```csharp
// Check for SQL injection
if (InputValidationHelper.ContainsSqlInjection(input))
{
    // Handle malicious input
}

// Check for XSS
if (InputValidationHelper.ContainsXss(input))
{
    // Handle malicious input
}

// Validate email format
if (!InputValidationHelper.IsValidEmail(email))
{
    // Handle invalid email
}
```

### Input Sanitization

```csharp
// HTML encode input to prevent XSS
var sanitized = InputValidationHelper.SanitizeInput(userInput);
```

### Simple Validation

```csharp
var (isValid, errorMessage) = InputValidationHelper.ValidateInput(input, "FieldName");
if (!isValid)
{
    return Results.BadRequest(errorMessage);
}
```

## Methods

### `ValidateLoginInput(string email, string password)`

Validates login credentials with comprehensive checks.

- **Returns**: `(bool IsValid, List<string> Errors)`

### `ValidateRegistrationInput(string email, string password)`

Validates registration input (currently same as login validation).

- **Returns**: `(bool IsValid, List<string> Errors)`

### `ValidateStringInput(...)`

Customizable validation with multiple parameters.

- **Parameters**:
  - `input`: String to validate
  - `fieldName`: Name for error messages
  - `required`: Whether field is required (default: true)
  - `minLength`: Minimum length (default: 0)
  - `maxLength`: Maximum length (default: int.MaxValue)
  - `checkSqlInjection`: Enable SQL injection check (default: true)
  - `checkXss`: Enable XSS check (default: true)
- **Returns**: `(bool IsValid, List<string> Errors)`

### `ValidateInput(string input, string fieldName)`

Simple validation for SQL injection and XSS.

- **Returns**: `(bool IsValid, string ErrorMessage)`

### `ContainsSqlInjection(string input)`

Checks if input contains SQL injection patterns.

- **Returns**: `bool`

### `ContainsXss(string input)`

Checks if input contains XSS patterns.

- **Returns**: `bool`

### `SanitizeInput(string input)`

HTML encodes input to prevent XSS.

- **Returns**: `string`

### `IsValidEmail(string email)`

Validates email format.

- **Returns**: `bool`

### `IsValidLength(string input, int minLength, int maxLength)`

Checks if input length is within bounds.

- **Returns**: `bool`

### `IsAlphanumericWithSpecialChars(string input, string allowedSpecialChars)`

Validates input contains only alphanumeric and specified special characters.

- **Returns**: `bool`

## Best Practices

1. **Always validate user input** before processing or storing it
2. **Use parameterized queries** in addition to validation (defense in depth)
3. **Sanitize output** when displaying user-generated content
4. **Keep validation patterns updated** as new attack vectors emerge
5. **Log validation failures** for security monitoring
6. **Combine with other security measures** like rate limiting and CAPTCHA

## Security Notes

⚠️ **Important**: This validation helper is a defense-in-depth measure. Always use:

- **Parameterized queries** or **Entity Framework** to prevent SQL injection
- **Content Security Policy (CSP)** headers to prevent XSS
- **Input validation** on both client and server side
- **Output encoding** when displaying user content

## Integration

The validation helper is already integrated into:

- `/api/login` endpoint
- `/api/register` endpoint

You can extend it to other endpoints as needed.
