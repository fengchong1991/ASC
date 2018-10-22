using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Models.MasterDataKeyViewModels
{
    public class MasterKeysViewModel
    {
        public List<MasterKeysViewModel> MasterKeys { get; set; }
        public MasterKeysViewModel MasterKeyInContext { get; set; }
        public bool IsEdit { get; set; }
    }
}
