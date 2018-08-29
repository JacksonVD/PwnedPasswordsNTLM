using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Basic binary search to be used on a sorted Pwned Passwords dataset

class PwnedPasswordsNTLM
{

    static void Main(String[] args)
    {
        if (args.Length!=0)
        {
            if (args[0] != null && args[1] != null && args[2] != null)
            {
                // Input and output files
                try
                {
                    // Stopwatch for timing
                    Stopwatch stopwatch = new Stopwatch();
                    stopwatch.Start();

                    System.IO.StreamReader inFile = new System.IO.StreamReader(@args[1]);
                    System.IO.StreamWriter outFile = new System.IO.StreamWriter(@args[2]);

                    String line;

                    // Continue to read the input file while not EOF
                    while ((line = inFile.ReadLine()) != "" && line != null)
                    {
                        // If readFile returns true, password exists in the dataset
                        if (readFile(line.Split(':')[1], args[0]))
                        {
                            // Output to the output file that the user has a breached password
                            outFile.WriteLine("{0} has a pwned password", line.Split(':')[0]);
                            Console.WriteLine("{0} has a pwned password", line.Split(':')[0]);
                        }

                    }

                    // Stop stopwatch and output time taken
                    stopwatch.Stop();
                    Console.WriteLine("\nCompleted in: {0} ms", stopwatch.ElapsedMilliseconds);
                    Console.WriteLine("All pwned users output to {0}", @args[2]);

                    // Close the output and input files after reading and writing
                    outFile.Close();
                    inFile.Close();
                }
                catch (FileNotFoundException)
                {
                    Console.WriteLine("File does not exist\n");
                }
                catch (IOException)
                {
                    Console.WriteLine("File I/O error\n");
                }
            }
        }
        else
        {
            Console.WriteLine("Incorrect parameters.\nUsage: PwnedPasswordsNTLM <DATASET> <INPUT FILE> <OUTPUT FILE>");
        }
    }

    static Boolean readFile(String searchValue, String inFile)
    {
        // Declaration and initialisation for variables to be used
        Boolean passwordFound = false;
        Int64 lower = 0;
        Int64 upper = 0;
        Int64 bytes;
        Int64 totalPasswords;

        // Convert the current password to be searched for to upper case
        searchValue = searchValue.ToUpper();

        // Create a file stream, reading the file starting from the end
        try
        {
            FileStream file = new FileStream(@inFile, FileMode.Open);
            file.Seek(0, SeekOrigin.End);

            // Get the number of bytes in the file (position returns number of bytes)
            bytes = file.Position;

            // Get total passwords by dividing by NTLM length + 2 - 1
            totalPasswords = (bytes / 34) - 1;

            // Initialise the upper bound
            upper = totalPasswords;

            // Binary search function
            while (lower <= upper)
            {
                // Set the middle of stream to the lower + upper + 1, all divided by 2
                Int64 position = (lower + upper + 1) / 2;

                // Set buffer string to return value from GetRecord function
                string buffer = getRecord(file, position);

                // If the two values are equal..
                if (searchValue.Equals(buffer))
                {
                    // Set the lower and upper bounds to 1 and 0 respectively, to stop searching
                    lower = 1;
                    upper = 0;
                    // Set passwordFound boolean to true - password found
                    passwordFound = true;
                }
                // If the requesting password hash is greater than the current hash
                else if (searchValue.CompareTo(buffer) > 0)
                {
                    // Set lower equal to the middle value + 1 - need to move up the file
                    lower = position + 1;
                }
                // If the requesting password hash is lower than the current hash
                else if (searchValue.CompareTo(buffer) < 0)
                {
                    // Set upper equal to the middle value - 1 - need to move down the file
                    upper = position - 1;
                }
            }

            // Close the file after reading
            file.Close();
        }
        catch
        {
            throw new IOException();
        }

        // Return the passwordFound boolean
        return passwordFound;
    }


    static String getRecord(FileStream inFile, Int64 position)
    {
        // Create buffer array of NTLM hash length + 1
        String record;
        byte[] buffer = new byte[33];

        // Set the stream to the required hash start position
        inFile.Seek(((long)(position) * 34), SeekOrigin.Begin);

        // Read 32 chararacters (size of 1 NTLM hash) into the buffer byte array
        inFile.Read(buffer, 0, 32);

        // Convert from byte array to string and remove null terminator character
        record = System.Text.Encoding.UTF8.GetString(buffer);
        record = record.Replace("\0", string.Empty);

        // Return buffer as a string
        return record;
    }
}
