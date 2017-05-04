using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;
using NLog;

namespace JWTDemoForNetCore
{
    public class CustomBearerEvents : Microsoft.AspNetCore.Authentication.JwtBearer.IJwtBearerEvents
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = context => Task.FromResult(0);


        /// <summary>
        /// Invoked before a challenge is sent back to the caller.
        /// </summary>
        public Func<JwtBearerChallengeContext, Task> OnChallenge { get; set; } = context => Task.FromResult(0);


        Task IJwtBearerEvents.AuthenticationFailed(AuthenticationFailedContext context)
        {
            _logger.Info("AuthenticationFailed");
            return OnAuthenticationFailed(context);
        }

        Task IJwtBearerEvents.Challenge(JwtBearerChallengeContext context)
        {
            _logger.Info("Challenge");
            return OnChallenge(context);
        }

        Task IJwtBearerEvents.MessageReceived(MessageReceivedContext context)
        {
            _logger.Info("MessageReceived");
            return OnMessageReceived(context);
        }

        Task IJwtBearerEvents.TokenValidated(TokenValidatedContext context)
        {
            _logger.Info("TokenValidated");
            return OnTokenValidated(context);
        }
    }
}