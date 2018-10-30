using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ASC.Business.Interfaces;
using ASC.Models.Models;
using ASC.Utilities;
using ASC.Web.Models.MasterDataViewModels;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ASC.Web.Controllers
{
    [Authorize(Roles = "Admin")]
    public class MasterDataController : Controller
    {
        private readonly IMasterDataOperations _masterData;
        private readonly IMapper _mapper;


        public MasterDataController(IMasterDataOperations masterData, IMapper mapper)
        {
            _masterData = masterData;
            _mapper = mapper;
        }

        [HttpGet]
        public async Task<IActionResult> MasterKeys()
        {
            var masterKeys = await _masterData.GetAllMasterKeysAsync();
            var masterKeysViewModel = _mapper.Map<List<MasterDataKey>, List<MasterDataKeyViewModel>>(masterKeys);

            // Hold all Master Keys in session
            HttpContext.Session.SetSession("MasterKeys", masterKeysViewModel);
              
            return View(new MasterKeysViewModel
            {
                MasterKeys = masterKeysViewModel?.ToList(),
                IsEdit = false
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> MasterKeys(MasterKeysViewModel masterKeys)
        {
            masterKeys.MasterKeys = HttpContext.Session.GetSession<List<MasterDataKeyViewModel>> ("MasterKeys");

            if (!ModelState.IsValid)
            {
                return View(masterKeys);
            }

            var masterKey = _mapper.Map<MasterDataKeyViewModel, MasterDataKey>(masterKeys.MasterKeyInContext);

            if (masterKeys.IsEdit)
            {
                // Update Master Key
                await _masterData.UpdateMasterKeyAsync(masterKeys.MasterKeyInContext.PartitionKey, masterKey);
            }
            else
            {
                // Insert Master Key
                masterKey.RowKey = Guid.NewGuid().ToString();
                masterKey.PartitionKey = masterKey.Name;
                await _masterData.InsertMasterKeyAsync(masterKey);
            }
            return RedirectToAction("MasterKeys");
        }
    }
}