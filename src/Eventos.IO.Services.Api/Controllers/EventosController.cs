using System;
using System.Collections.Generic;
using AutoMapper;
using Eventos.IO.Application.Interfaces;
using Eventos.IO.Application.ViewModels;
using Eventos.IO.Domain.Core.Bus;
using Eventos.IO.Domain.Core.Notifications;
using Eventos.IO.Domain.Eventos.Commands;
using Eventos.IO.Domain.Eventos.Repository;
using Eventos.IO.Domain.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Eventos.IO.Services.Api.Controllers
{
    public class EventosController : BaseController
    {
        private readonly IEventoAppService _eventoAppService;
        private readonly IBus _bus;
        private readonly IEventoRepository _eventoRepository;
        private readonly IMapper _mapper;

        public EventosController(IDomainNotificationHandler<DomainNotification> notifications, 
                                 IUser user, 
                                 IBus bus, IEventoAppService eventoAppService, 
                                 IEventoRepository eventoRepository, 
                                 IMapper mapper) : base(notifications, user, bus)
        {
            _eventoAppService = eventoAppService;
            _eventoRepository = eventoRepository;
            _mapper = mapper;
            _bus = bus;
        }

        [HttpGet]
        [Route("eventos")]
        [AllowAnonymous]
        public IEnumerable<EventoViewModel> Get()
        {
            return _eventoAppService.ObterTodos();
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("eventos/{id:guid}")]
        public EventoViewModel Get(Guid id, int version)
        {
            return _eventoAppService.ObterPorId(id);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("eventos/categorias")]
        public IEnumerable<CategoriaViewModel> ObterCategorias()
        {
            return _mapper.Map<IEnumerable<CategoriaViewModel>>(_eventoRepository.ObterCategorias());
        }

        [HttpPost]
        [Route("eventos")]
        [Authorize(Policy = "PodeGravar")]
        public IActionResult Post([FromBody]EventoViewModel eventoViewModel)
        {
            if (!ModelState.IsValid)
            {
                NotificarErroModelInvalida();
                return Response();
            }

            var eventoCommand = _mapper.Map<RegistrarEventoCommand>(eventoViewModel);

            _bus.SendCommand(eventoCommand);
            return Response(eventoCommand);
        }

        [HttpPut]
        [Route("eventos")]
        [Authorize(Policy = "PodeGravar")]
        public IActionResult Put([FromBody]EventoViewModel eventoViewModel)
        {
            if (!ModelState.IsValid)
            {
                NotificarErroModelInvalida();
                return Response();
            }

            _eventoAppService.Atualizar(eventoViewModel);
            return Response(eventoViewModel);
        }

        [HttpDelete]
        [Route("eventos/{id:guid}")]
        [Authorize(Policy = "PodeGravar")]
        public IActionResult Delete(Guid id)
        {
            _eventoAppService.Excluir(id);
            return Response();
        }
    }
}
