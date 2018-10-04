using Newtonsoft.Json;
using System;

namespace ASC.Utilities
{
    public static class ObjectExtensions
    {
        public static T CopyObject<T>(this object objSource)
        {
            var serialized = JsonConvert.SerializeObject(objSource);
            return JsonConvert.DeserializeObject<T>(serialized);
        }
    }
}
