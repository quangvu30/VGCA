using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace VGCA
{
    public class Logger
    {
        public static void LogSignatureInfoList(List<PDFSignatureInfo> signatureInfoList)
        {
            foreach (var signatureInfo in signatureInfoList)
            {
                LogFields(signatureInfo);
            }
        }

        public static void LogFields<T>(T obj)
        {
            Type type = obj.GetType();
            FieldInfo[] fields = type.GetFields(BindingFlags.Public | BindingFlags.Instance);

            foreach (var field in fields)
            {
                object value = field.GetValue(obj);

                // Handle array and complex object logging
                if (value is byte[] byteArray)
                {
                    Console.WriteLine($"{field.Name}: {BitConverter.ToString(byteArray)}");
                }
                else if (value is Dictionary<SignatureValidity, string> dictionary)
                {
                    Console.WriteLine($"{field.Name}: {string.Join(", ", dictionary.Select(kvp => $"{kvp.Key}: {kvp.Value}"))}");
                }
                else
                {
                    Console.WriteLine($"{field.Name}: {value}");
                }
            }
        }
    }
}
