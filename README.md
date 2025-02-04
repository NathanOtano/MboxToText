Mbox Conversation Converter with Stacking
This Python script converts Gmail mbox files into conversation-based text files, stacking multiple conversations into single files up to user-defined limits (maximum words per file and maximum file size in MB). It’s designed to optimize the number and size of reference files for uploading as inputs to AI models.

Features
Conversation Grouping:
Emails are grouped into conversations based on a normalized (and decoded) subject header.
Filtering:
Option to include only messages sent by you (using your sender email address), thereby filtering out conversations in which you did not participate.
Stacking Conversations:
Processed conversation texts are combined (“stacked”) into output files. You can set limits on the maximum number of words and maximum file size (in MB) per output file. Once a limit is reached, a new file is started.
Multi-threading:
Conversations are processed concurrently using a thread pool, which speeds up conversion on large mbox files.
Graphical User Interface (GUI):
Built with Tkinter, the GUI lets you:
Select an mbox file.
Enter your sender email address.
Choose whether to filter out emails not sent by you.
Select an output folder.
Specify maximum words per file and maximum file size per file.
Monitor conversion progress via a progress bar, status label, and log area.
Persistent Settings:
Your last-used settings (e.g., selected mbox file, sender email, filtering option, output folder, and stacking limits) are saved to a JSON file (mbox_converter_settings.json) and reloaded the next time you run the script.
Requirements
Python 3.x
Tkinter (usually included with Python)
BeautifulSoup 4
Install with:
bash
Copier
pip install beautifulsoup4
Installation
Clone or Download the Script:
Save the script file (for example, as mbox_converter.py) into a folder on your computer.

Install Dependencies:
Open a terminal (or command prompt) and run:

bash
Copier
pip install beautifulsoup4
Usage
Run the Script:
In a terminal, navigate to the folder containing mbox_converter.py and execute:

bash
Copier
python mbox_converter.py
Using the GUI:

Select mbox File: Click the Browse button to choose your mbox file.
Enter Sender Email: Type your sender email address. This is used to identify which messages are yours.
Filter Option: Check the option “Only include emails sent by me (exclude others even in conversation)” if you wish to only include your messages.
Select Output Folder: Click the Browse Folder button to choose where the output files will be saved.
Set Stacking Limits:
Enter the maximum number of words per output file in the “Max words per file” box.
Enter the maximum size (in MB) per output file in the “Max size (MB) per file” box.
Convert: Click the Convert button to start the conversion process.
Monitor Progress:
A progress bar, status label, and log area will update in real time as the conversion proceeds.
Persistent Settings:
Your settings are automatically saved when you close the application and loaded the next time you run the script.
Output Files:
The script stacks processed conversations into files (named sequentially as stack_1.txt, stack_2.txt, etc.) in the selected output folder. Each file will contain as many conversations as possible without exceeding the specified word count or file size limits.

Troubleshooting
Invalid File Names:
If you encounter errors related to file naming, the script’s filename sanitization should handle most cases. Ensure your mbox file’s subject headers are decodable.
Conversion Errors:
Check the log area in the GUI for error messages during conversion. Make sure that your mbox file is valid and that all dependencies are installed.
Settings Not Loading:
If the settings do not appear to load, ensure that the script has permission to read and write in the directory containing mbox_converter_settings.json.
License
This project is provided as-is, without any warranty. You are free to modify and distribute this script as needed.

Acknowledgements
This script uses BeautifulSoup for HTML parsing.
It is built using Python's standard libraries, including tkinter, mailbox, and concurrent.futures.
You can include this README file (for example, named README.md) along with your script distribution. This file explains the functionality, requirements, usage instructions, and other details for users of your converter. Enjoy!






