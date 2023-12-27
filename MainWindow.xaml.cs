using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
namespace duomenukodavimas
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string fileContent = string.Empty;
        private string filePath = string.Empty;
        private ComboBoxItem? selectedItem = null;
        private string password = string.Empty;
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                filePath = openFileDialog.FileName;
                Label1.Content = openFileDialog.FileName;
                var fileStream = openFileDialog.OpenFile();
                using (StreamReader reader = new StreamReader(fileStream))
                {
                    fileContent = reader.ReadToEnd();
                }
            }
            
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            var selectedItemText = selectedItem?.Content.ToString();


            if (File.Exists(filePath) && !string.IsNullOrEmpty(password))
            {
                if (selectedItem != null && selectedItemText == "AES")
                {
                    AesUzkoduoti(password, fileContent); 
                    MessageBox.Show("AES encryption successful!");
                }
                else if (selectedItem != null && selectedItemText == "3DES")
                {
                    TripleDESUzkoduoti(password, fileContent); 
                    MessageBox.Show("3DES encryption successful!");
                }
                else
                {
                    MessageBox.Show("Invalid algorithm selected: " + selectedItemText);
                }
            }
        }


        private void Button_Click_2(object sender, RoutedEventArgs e)
        {
            var selectedItemText = selectedItem?.Content.ToString();

            if (File.Exists(filePath) && !string.IsNullOrEmpty(password))
            {
                if (selectedItem != null && selectedItemText == "AES")
                {
                    string decryptedContent = DekoduotiInformacija(password, filePath);
                    MessageBox.Show("Decrypted Content:\n" + decryptedContent);
                }
                else if (selectedItem != null && selectedItemText == "3DES")
                {
                    string decryptedContent = TripleDESAtkoduoti(password, filePath);
                    MessageBox.Show("Decrypted Content:\n" + decryptedContent);
                }
                else
                {
                    MessageBox.Show("Invalid algorithm selected: " + selectedItemText);
                }
            }
        }

        private void encryptionComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

            selectedItem = encryptionComboBox.SelectedItem as ComboBoxItem;

            MessageBox.Show("Selected Item Text: " + selectedItem + "\n");
        }

        public static void AesUzkoduoti(string password, string informacija)
        {
            try
            {
                using (Aes aesAlg = Aes.Create())
                {
                    using (Rfc2898DeriveBytes keyDerivation = new Rfc2898DeriveBytes(password, aesAlg.IV, 10000))
                    {
                        byte[] key = keyDerivation.GetBytes(aesAlg.KeySize / 8);
                        byte[] iv = aesAlg.IV;

                        using (FileStream fileStream = new FileStream("AES_Uzsifruota.txt", FileMode.Create))
                        {
                            fileStream.Write(iv, 0, iv.Length);

                            using (CryptoStream cryptoStream = new CryptoStream(
                                fileStream,
                                aesAlg.CreateEncryptor(key, iv),
                                CryptoStreamMode.Write))
                            {
                                using (StreamWriter encryptWriter = new StreamWriter(cryptoStream))
                                {
                                    encryptWriter.WriteLine(informacija);
                                }
                            }
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Nepavyko uzifruoti" + ex);
            }
        }

        public static void TripleDESUzkoduoti(string password, string informacija)
        {
            try
            {
                using (TripleDES desAlg = TripleDES.Create())
                {
                    using (Rfc2898DeriveBytes keyDerivation = new Rfc2898DeriveBytes(password, desAlg.IV, 10000))
                    {
                        byte[] key = keyDerivation.GetBytes(desAlg.KeySize / 8);
                        byte[] iv = desAlg.IV;

                        using (FileStream fileStream = new FileStream("3DES_Uzsifruota.txt", FileMode.Create))
                        {
                            fileStream.Write(iv, 0, iv.Length);

                            using (CryptoStream cryptoStream = new CryptoStream(
                                fileStream,
                                desAlg.CreateEncryptor(key, iv),
                                CryptoStreamMode.Write))
                            {
                                using (StreamWriter encryptWriter = new StreamWriter(cryptoStream))
                                {
                                    encryptWriter.WriteLine(informacija);
                                }
                            }
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Nepavyko uzifruoti" + ex);
            }
        }

        private void TextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            password = passInput.Text;
        }

        public static string DekoduotiInformacija(string password, string filePath)
        {
            try
            {
                using (Aes aesAlg = Aes.Create())
                {
                    using (FileStream fileStream = new FileStream(filePath, FileMode.Open))
                    {
                        byte[] iv = new byte[aesAlg.IV.Length];
                        fileStream.Read(iv, 0, iv.Length);

                        using (Rfc2898DeriveBytes keyDerivation = new Rfc2898DeriveBytes(password, iv, 10000))
                        {
                            byte[] key = keyDerivation.GetBytes(aesAlg.KeySize / 8);

                            using (CryptoStream cryptoStream = new CryptoStream(
                                fileStream,
                                aesAlg.CreateDecryptor(key, iv),
                                CryptoStreamMode.Read))
                            {
                                using (StreamReader decryptReader = new StreamReader(cryptoStream))
                                {
                                    return decryptReader.ReadToEnd();
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Nepavyko dekoduoti" + ex);
                return string.Empty;
            }
        }

        public static string TripleDESAtkoduoti(string password, string filePath)
        {
            try
            {
                using (TripleDES desAlg = TripleDES.Create())
                {
                    using (FileStream fileStream = new FileStream(filePath, FileMode.Open))
                    {
                        byte[] iv = new byte[desAlg.IV.Length];
                        fileStream.Read(iv, 0, iv.Length);

                        using (Rfc2898DeriveBytes keyDerivation = new Rfc2898DeriveBytes(password, iv, 10000))
                        {
                            byte[] key = keyDerivation.GetBytes(desAlg.KeySize / 8);

                            using (CryptoStream cryptoStream = new CryptoStream(
                                fileStream,
                                desAlg.CreateDecryptor(key, iv),
                                CryptoStreamMode.Read))
                            {
                                using (StreamReader decryptReader = new StreamReader(cryptoStream))
                                {
                                    return decryptReader.ReadToEnd();
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Nepavyko atkoduoti" + ex);
                return string.Empty;
            }
        }

    }
}