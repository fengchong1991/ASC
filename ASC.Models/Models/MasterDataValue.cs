using ASC.Models.BaseTypes;
using System;
using System.Collections.Generic;
using System.Text;

namespace ASC.Models.Models
{
    public class MasterDataValue : BaseEntity, IAuditTracker
    {
        public bool IsActive { get; set; }
        public string Name { get; set; }

        public MasterDataValue()
        {

        }

        public MasterDataValue(string partitionKey, string value)
        {
            this.PartitionKey = partitionKey;
            this.RowKey = Guid.NewGuid().ToString();
        }
    }
}
