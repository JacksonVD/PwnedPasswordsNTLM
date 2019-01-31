using System;
using System.Diagnostics;
using System.IO;

// Basic binary search to be used on a sorted Pwned Passwords dataset
// - download the ordered by hash NTLM set from https://haveibeenpwned.com/passwords

class PwnedPasswordsNTLM
{
    /*
     * METHOD: main
     * PARAMS: args (String[])
     *           Three arguments - data set location, hashes location, output location
     * PURPOSE: Flow of execution - opens files, calls file reader function, closes files
     * EXPORTS: NONE
     */
    static void Main(String[] args)
    {
        // Confirm correct number of arguments given - dataset, input, output locations
        if (args.Length == 3)
        {
            try
            {
                // Stopwatch for timing
                Stopwatch stopwatch = new Stopwatch();
                stopwatch.Start();

                // Attempt to open the input and output files
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
                        // NOTE: To speed up checking, you can get rid of this line.
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

            // Output to user if file not found or I/O errors occur
            catch (FileNotFoundException)
            {
                Console.WriteLine("File does not exist\n");
            }
            catch (IOException)
            {
                Console.WriteLine("File I/O error\n");
            }
        }
        // If the user doesn't supply the correct parameters, output the program's usage
        else
        {
            Console.WriteLine("Incorrect parameters.\nUsage: PwnedPasswordsNTLM <DATASET> <INPUT FILE> <OUTPUT FILE>");
        }
    }

    /*
     * METHOD: readFile
     * PARAMS: searchValue (String)
     *           Value to search for - the NTLM hash
     *         inFile (String)
     *           Name of the input file
     * PURPOSE: Binary search method to look for the current hash in the input file
     * EXPORTS: passwordFound (Boolean)
     *            Whether or not the hash exists in the input file
     */
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

            // Get total passwords by dividing by NTLM length + 2
            totalPasswords = (bytes / 34);

            // Initialise the upper bound
            upper = totalPasswords;

            // Binary search function
            while (lower <= upper)
            {
                // Set the middle of stream to the lower + upper + 1, all divided by 2
                Int64 position = (lower + upper + 1) / 2;

                // Set buffer string to return value from GetRecord function
                string buffer = getRecord(file, position, searchValue);

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
        // Throw IOExceptions up to main
        catch
        {
            throw new IOException();
        }

        // Return the passwordFound boolean
        return passwordFound;
    }

    /*
     * METHOD: getRecord
     * PARAMS: inFile (FileStream)
     *           File stream for the input file
     *         position (Int64)
     *           Current position in the file to grab the next hash from
     * PURPOSE: Gets the next hash from the file stream given the current position
     * EXPORTS: record (String)
     *            The hash obtained from the required position
     */

    static String getRecord(FileStream inFile, Int64 position, String searchVal)
    {
        String record;

        // Create buffer array of NTLM hash length + 1
        byte[] buffer = new byte[33];

        // Set the stream to the required hash start position
        inFile.Seek(((long)(position) * 34 ), SeekOrigin.Begin);

        // Read 32 chararacters (size of 1 NTLM hash) into the buffer byte array
        inFile.Read(buffer, 0, 32);
           
        // Convert from byte array to string and remove null terminator character
        record = System.Text.Encoding.UTF8.GetString(buffer);

        // Get the current file position, in case we need it further on
        Int64 curr = inFile.Position;

        // In order to allow for users using the frequency of occurrences, this check
        // is required - essentially scan for a \n or : in the current string. If these 
        // characters exist, it means an incomplete hash was picked up.
        // The frequency tends to mess with the easy pickup of the hash, so we need these extra checks
        if (record.Contains("\n") || record.Contains(":"))
        {
            // Clear the buffer
            Array.Clear(buffer, 0, buffer.Length);
            String origRecord = record;

            // Anything before the \n in the string is part of the hash we want to look at
            String origHash = record.Split('\n')[0];
            String oldHash = "";

            // If the original hash contains :, then it includes a frequency for the prior hash
            if (origHash.Contains(":"))
            {
                oldHash = origHash.Split(':')[0];

                // Move back to where the current hash would have started
                inFile.Seek(((long)(position) * 34) - (32 - oldHash.Length), SeekOrigin.Begin);

                // Read the beginning of the hash into the buffer
                inFile.Read(buffer, 0, (32 - oldHash.Length));

                // Combine the start and end of the hash
                record = System.Text.Encoding.UTF8.GetString(buffer) + oldHash;
            }
            // Otherwise, go forward instead of backward - the "original" hash would only contain the 
            // frequency information in this case, so it is easier to get the next hash in the file.
            else
            {
                // If \r exists in the hash, then more than one extra character needs to be read in
                // (occasionally, only one character needs to be read in as the original buffer
                //  would have been \n{some hash}.)
                if (origHash.Contains("\r"))
                {
                    // The old hash will likely just contain the frequency information
                    oldHash = origHash.Split('\r')[0];
                    Array.Clear(buffer, 0, buffer.Length);

                    // Get the hash length including the \r and \n (2 extra characters)
                    int oldHashLength = oldHash.Length + 2;

                    // Seek back to the original position as we will now be reading in extra characters
                    inFile.Seek(curr, SeekOrigin.Begin);

                    // Read oldHashLength more characters into our buffer
                    inFile.Read(buffer, 0, oldHashLength);

                    // Get the part of the current hash that we already have, and append the rest of the hash
                    record = origRecord.Split('\n')[1];
                    record = record + System.Text.Encoding.UTF8.GetString(buffer);

                }
                // If \r does not exist in the hash, then we only need one extra character.
                else
                {
                    // Clear the buffer
                    Array.Clear(buffer, 0, buffer.Length);

                    // Read in one extra character
                    inFile.Read(buffer, 0, 1);

                    // Append the final character of the hash
                    record = origRecord.Split('\n')[1];
                    record = record + System.Text.Encoding.UTF8.GetString(buffer);
                }
            }
        }

        // Replace the NULL character with string.Empty
        record = record.Replace("\0", string.Empty);

        // Return the current hash
        return record;
    }
}
