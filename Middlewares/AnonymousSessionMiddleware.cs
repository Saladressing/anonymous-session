namespace anonymous_session.Middlewares
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Authentication;
    using System.Security.Claims;

    public class AnonymousSessionMiddleware
    {
        private readonly RequestDelegate _next;

        public AnonymousSessionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async System.Threading.Tasks.Task InvokeAsync(HttpContext context)
        {
            if (!context.User.Identity.IsAuthenticated)
            {
                if (string.IsNullOrEmpty(context.User.FindFirstValue(ClaimTypes.Anonymous)))
                {
                    var claim = new Claim(ClaimTypes.Anonymous, System.Guid.NewGuid().ToString());
                    context.User.AddIdentity(new ClaimsIdentity(new[] { claim }));

                    string scheme = Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme;
                    await context.SignInAsync(scheme, context.User, new AuthenticationProperties { IsPersistent = false });
                }
            }
            
            await _next(context);
        }
    }
}