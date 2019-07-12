using Eventos.IO.Domain.Core.Notifications;
using Eventos.IO.Domain.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Eventos.IO.Infra.CrossCutting.Identity.Models;
using Microsoft.Extensions.Logging;
using Eventos.IO.Domain.Core.Bus;
using System.Threading.Tasks;
using Eventos.IO.Infra.CrossCutting.Identity.Models.AccountViewModels;
using Eventos.IO.Domain.Organizadores.Commands;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Eventos.IO.Infra.CrossCutting.Identity.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Eventos.IO.Services.Api.Controllers
{
    public class AccountController : BaseController
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger _logger;
        private readonly IBus _bus;

        private readonly JwtTokenOptions _jwtTokenOptions;

        public AccountController(
                    UserManager<ApplicationUser> userManager,
                    SignInManager<ApplicationUser> signInManager,
                    ILoggerFactory loggerFactory,
                    IOptions<JwtTokenOptions> jwtTokenOptions,
                    IBus bus,
                    IDomainNotificationHandler<DomainNotification> notifications, 
                    IUser user) : base(notifications, user, bus)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _bus = bus;
            _jwtTokenOptions = jwtTokenOptions.Value;

            ThrowIfInvalidOptions(_jwtTokenOptions);
            _logger = loggerFactory.CreateLogger<AccountController>();
        }

        private static long ToUnixEpochDate(DateTime date)
      => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);

        [HttpPost]
        [AllowAnonymous]
        [Route("nova-conta")]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model, int version)
        {
            if (version == 2)
            {
                return Response(new { Message = "API V2 não disponível" });
            }

            if (!ModelState.IsValid) return Response(model);

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                var registroCommand = new RegistrarOrganizadorCommand(Guid.Parse(user.Id), model.Nome, model.CPF, user.Email);
                _bus.SendCommand(registroCommand);

                if (!OperacaoValida())
                {
                    await _userManager.DeleteAsync(user);
                    return Response(model);
                }

                _logger.LogInformation(1, "Usuario criado com sucesso!");
                var response = GerarTokenUsuario(new LoginViewModel { Email = model.Email, Password = model.Password });
                return Response(response);
            }
            AdicionarErrosIdentity(result);
            return Response(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("conta")]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                NotificarErroModelInvalida();
                return Response(model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, true);

            if (result.Succeeded)
            {
                _logger.LogInformation(1, "Usuario logado com sucesso");
                var response = GerarTokenUsuario(model);
                return Response(response);
            }

            NotificarErro(result.ToString(), "Falha ao realizar o login");
            return Response(model);
        }

        private async Task<object> GerarTokenUsuario(LoginViewModel login)
        {
            var user = await _userManager.FindByEmailAsync(login.Email);
            var userClaims = await _userManager.GetClaimsAsync(user);

            userClaims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            userClaims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            userClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, await _jwtTokenOptions.JtiGenerator()));
            userClaims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_jwtTokenOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64));

            var jwt = new JwtSecurityToken(
                  issuer: _jwtTokenOptions.Issuer,
                  audience: _jwtTokenOptions.Audience,
                  claims: userClaims,
                  notBefore: _jwtTokenOptions.NotBefore,
                  expires: _jwtTokenOptions.Expiration,
                  signingCredentials: _jwtTokenOptions.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                access_token = encodedJwt,
                expires_in = (int)_jwtTokenOptions.ValidFor.TotalSeconds,
                user = user
            };

            return response;
        }


        private static void ThrowIfInvalidOptions(JwtTokenOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtTokenOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(JwtTokenOptions.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(JwtTokenOptions.JtiGenerator));
            }
        }
    }
}