using Microsoft.AspNetCore.Mvc.Rendering;
using System;
using System.Collections.Generic;

namespace Eventos.IO.Application.ViewModels
{
    public class CategoriaViewModel
    {
        public Guid Id { get; set; }
        public string Nome { get; set; }

        public SelectList Categorias()
        {
            return new SelectList(ListarCategorias(), "Id", "Nome");
        }

        public List<CategoriaViewModel> ListarCategorias()
        {
            var categoriasList = new List<CategoriaViewModel>()
            {
                new CategoriaViewModel(){ Id = new Guid("ac381ba8-c187-482c-a5cb-899ad7176137"), Nome = "Congresso"},
                new CategoriaViewModel(){ Id = new Guid("1bbfa7e9-5a1f-4cef-b209-58954303dfc3"), Nome = "Meetup"},
                new CategoriaViewModel(){ Id = new Guid("d443f7c6-04e5-4f48-8fe0-9e6726b4fdb0"), Nome = "Workshop"}
            };

            return categoriasList;
        }
    }
}