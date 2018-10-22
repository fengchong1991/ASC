using ASC.Models.Models;
using ASC.Web.Models.MasterDataKeyViewModels;
using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Models.MappingProfile
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<MasterDataKey, MasterDateKeyViewModel>().ReverseMap();
        }
    }
}
