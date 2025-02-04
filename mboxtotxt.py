import os
import json
import mailbox
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.header import decode_header

# --- Settings Persistence ---

SETTINGS_FILE = "mbox_converter_settings.json"

def load_settings():
    """Load saved settings from SETTINGS_FILE and update UI variables."""
    try:
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            settings = json.load(f)
        selected_file_var.set(settings.get("selected_file", ""))
        sender_email_var.set(settings.get("sender_email", ""))
        filter_non_sent_var.set(settings.get("filter_non_sent", True))
        output_folder_var.set(settings.get("output_folder", ""))
        max_words_var.set(str(settings.get("max_words", "1000")))
        max_mb_var.set(str(settings.get("max_mb", "1")))
    except Exception as e:
        print("Could not load settings:", e)

def save_settings():
    """Save current UI settings to SETTINGS_FILE."""
    settings = {
         "selected_file": selected_file_var.get(),
         "sender_email": sender_email_var.get(),
         "filter_non_sent": filter_non_sent_var.get(),
         "output_folder": output_folder_var.get(),
         "max_words": max_words_var.get(),
         "max_mb": max_mb_var.get()
    }
    try:
         with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
              json.dump(settings, f)
    except Exception as e:
         print("Could not save settings:", e)

def on_closing():
    """Called when the window is closing: save settings and exit."""
    save_settings()
    root.destroy()

# --- Helper Functions ---

def sanitize_filename(name):
    """
    Remove characters not allowed in file names—including control characters—and replace spaces with underscores.
    """
    name = re.sub(r'[<>:"/\\|?*\x00-\x1F]', '', name)
    name = name.strip().replace(" ", "_")
    if not name:
        name = "conversation"
    return name

def extract_email_address(from_field):
    """
    Extracts an email address from a 'From' header.
    For example, from "Nathan Otano <nathanotano@disnosc.fr>" returns "nathanotano@disnosc.fr".
    """
    from_field = str(from_field)  # ensure string
    match = re.search(r'<([^>]+)>', from_field)
    if match:
        return match.group(1).strip().lower()
    return from_field.strip().lower()

def clean_text(text):
    """
    Perform basic cleaning on the email text.
    """
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'On .*wrote:', '', text)
    return text.strip()

def extract_body(message):
    """
    Extract the plain text from an email message.
    If HTML-only, convert it to plain text.
    """
    body = ""
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                charset = part.get_content_charset() or 'utf-8'
                try:
                    part_text = part.get_payload(decode=True).decode(charset, errors='replace')
                    body += part_text + "\n"
                except Exception as e:
                    print(f"Error decoding part: {e}")
        if not body:
            for part in message.walk():
                content_type = part.get_content_type()
                if content_type == 'text/html':
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        html_content = part.get_payload(decode=True).decode(charset, errors='replace')
                        soup = BeautifulSoup(html_content, "html.parser")
                        body += soup.get_text(separator="\n") + "\n"
                    except Exception as e:
                        print(f"Error decoding HTML part: {e}")
    else:
        charset = message.get_content_charset() or 'utf-8'
        try:
            body = message.get_payload(decode=True).decode(charset, errors='replace')
        except Exception as e:
            print(f"Error decoding message: {e}")
    return clean_text(body)

def normalize_subject(subject):
    """
    Decode and normalize the subject by converting to lower-case, stripping whitespace,
    and removing common prefixes (e.g., 'Re:', 'Fwd:').
    """
    if not subject:
        subject = "No Subject"
    else:
        decoded_parts = decode_header(subject)
        subject_parts = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                try:
                    if encoding:
                        subject_parts.append(part.decode(encoding, errors="replace"))
                    else:
                        subject_parts.append(part.decode("utf-8", errors="replace"))
                except Exception as e:
                    subject_parts.append(part.decode("utf-8", errors="replace"))
            else:
                subject_parts.append(part)
        subject = " ".join(subject_parts)
    subject = subject.lower().strip()
    subject = re.sub(r'^(re|fwd):\s*', '', subject, flags=re.IGNORECASE)
    return subject

def process_conversation(norm_subject, messages, user_sender_email, filter_non_sent):
    """
    Process a single conversation group.
    - Return None if you (user_sender_email) did not participate.
    - If filter_non_sent is True, only include messages sent by you.
    - Returns a formatted string for the conversation.
    """
    participated = any(msg["sender"] == user_sender_email for msg in messages)
    if not participated:
        return None

    if filter_non_sent:
        messages = [msg for msg in messages if msg["sender"] == user_sender_email]
        if not messages:
            return None

    output = []
    output.append(f"Conversation: {norm_subject}")
    output.append("=" * 60)
    for msg in messages:
        speaker = "You" if msg["sender"] == user_sender_email else msg["sender"]
        output.append(f"{speaker}:")
        output.append(msg["body"])
        output.append("-" * 40)
    output.append("\n")
    return "\n".join(output)

def convert_mbox_to_stacked_files(mbox_file_path, user_sender_email, filter_non_sent,
                                  progress_callback, output_folder, max_words, max_size_bytes):
    """
    Converts an mbox file into a set of stacked conversation files stored in output_folder.
    Conversations are first grouped (and processed concurrently) and then combined (stacked)
    into output files so that each file does not exceed max_words or max_size_bytes.
    """
    user_sender_email = user_sender_email.strip().lower()
    mbox = mailbox.mbox(mbox_file_path)

    # Group messages by normalized subject.
    conversations = {}
    for message in mbox:
        subject = message.get("Subject", "No Subject")
        norm_subject = normalize_subject(subject)
        if norm_subject not in conversations:
            conversations[norm_subject] = []
        from_field = message.get("From", "unknown")
        sender = extract_email_address(from_field)
        body = extract_body(message)
        conversations[norm_subject].append({
            "sender": sender,
            "body": body,
            "subject": subject  # original subject (optional)
        })

    total_conversations = len(conversations)
    processed_count = 0
    results = {}  # mapping of norm_subject to processed conversation text

    # Process each conversation concurrently.
    with ThreadPoolExecutor() as executor:
        future_to_conv = {
            executor.submit(process_conversation, norm_subject, messages, user_sender_email, filter_non_sent): norm_subject
            for norm_subject, messages in conversations.items()
        }
        for future in as_completed(future_to_conv):
            conv_key = future_to_conv[future]
            try:
                conv_output = future.result()
            except Exception as e:
                conv_output = None
                print(f"Error processing conversation {conv_key}: {e}")
            results[conv_key] = conv_output
            processed_count += 1
            progress_callback(processed_count, total_conversations)

    # Stack conversation texts into files according to limits.
    stacked_files = []
    current_text = ""
    current_word_count = 0
    current_byte_count = 0

    # Iterate over conversations sorted by their normalized subject.
    for norm_subject in sorted(results.keys()):
        conv_output = results[norm_subject]
        if conv_output is not None:
            text = conv_output + "\n\n"  # add separation
            words = len(text.split())
            bytes_count = len(text.encode("utf-8"))
            # If adding this conversation would exceed either limit, finish current file.
            if current_text and ((current_word_count + words > max_words) or (current_byte_count + bytes_count > max_size_bytes)):
                stacked_files.append(current_text)
                current_text = text
                current_word_count = words
                current_byte_count = bytes_count
            else:
                current_text += text
                current_word_count += words
                current_byte_count += bytes_count
    if current_text.strip():
        stacked_files.append(current_text)

    # Write each stacked file with sequential naming.
    for i, content in enumerate(stacked_files, start=1):
        file_name = f"stack_{i}.txt"
        file_path = os.path.join(output_folder, file_name)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
    return output_folder

# --- Logging Function ---

def log_message(msg):
    """Append a log message to the log text widget."""
    log_text.config(state="normal")
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)
    log_text.config(state="disabled")

# --- GUI and Threading Functions ---

def browse_file():
    """Open a file dialog to select an mbox file."""
    file_path = filedialog.askopenfilename(
        filetypes=[("Mbox files", "*.mbox"), ("All files", "*.*")]
    )
    if file_path:
        selected_file_var.set(file_path)

def browse_output_folder():
    """Open a directory dialog to select an output folder."""
    folder = filedialog.askdirectory()
    if folder:
        output_folder_var.set(folder)

def start_conversion_thread():
    """Start the conversion in a background thread."""
    mbox_file_path = selected_file_var.get()
    user_sender_email = sender_email_var.get()
    filter_non_sent = filter_non_sent_var.get()
    output_folder = output_folder_var.get()

    if not mbox_file_path:
        messagebox.showerror("Error", "Please select an mbox file first!")
        return
    if not user_sender_email:
        messagebox.showerror("Error", "Please enter your sender email address!")
        return
    if not output_folder:
        messagebox.showerror("Error", "Please select an output folder!")
        return

    # Parse max words and max MB limits.
    try:
        max_words = int(max_words_var.get())
    except:
        messagebox.showerror("Error", "Please enter a valid integer for max words per file.")
        return
    try:
        max_mb = float(max_mb_var.get())
    except:
        messagebox.showerror("Error", "Please enter a valid number for max size (MB) per file.")
        return
    max_size_bytes = int(max_mb * 1000000)  # 1 MB = 1,000,000 bytes

    convert_button.config(state="disabled")
    status_label.config(text="Starting conversion...")
    log_message("Starting conversion...")

    thread = threading.Thread(target=worker_conversion,
                              args=(mbox_file_path, user_sender_email, filter_non_sent, output_folder, max_words, max_size_bytes))
    thread.start()

def worker_conversion(mbox_file_path, user_sender_email, filter_non_sent, output_folder, max_words, max_size_bytes):
    """Worker function to run conversion and update the GUI via callbacks."""
    def progress_callback(processed, total):
        root.after(0, update_progress, processed, total)
        root.after(0, log_message, f"Processed {processed} of {total} conversations")
    try:
        output_folder_used = convert_mbox_to_stacked_files(mbox_file_path, user_sender_email, filter_non_sent,
                                                            progress_callback, output_folder, max_words, max_size_bytes)
        root.after(0, log_message, "Conversion complete.")
        root.after(0, lambda: messagebox.showinfo("Success",
                                                  f"Conversion complete.\nFiles saved to:\n{output_folder_used}"))
    except Exception as e:
        root.after(0, log_message, f"Error during conversion: {e}")
        root.after(0, lambda: messagebox.showerror("Error", f"An error occurred during conversion:\n{e}"))
    finally:
        root.after(0, lambda: convert_button.config(state="normal"))
        root.after(0, status_label.config, {"text": "Conversion finished"})

def update_progress(processed, total):
    """Update the progress bar and status label."""
    progress_bar["maximum"] = total
    progress_bar["value"] = processed
    status_label.config(text=f"Processed {processed} of {total} conversations")

# --- GUI Implementation using Tkinter ---

root = tk.Tk()
root.title("Mbox Conversation Converter")

# Variables for input file, sender email, filtering, output folder, and stacking limits.
selected_file_var = tk.StringVar()
sender_email_var = tk.StringVar()
filter_non_sent_var = tk.BooleanVar(value=True)  # Default: only include emails sent by me
output_folder_var = tk.StringVar()
max_words_var = tk.StringVar(value="1000")   # Default max words per file
max_mb_var = tk.StringVar(value="1")         # Default max size in MB per file

# Load saved settings (if any).
load_settings()

# Main frame.
frame = tk.Frame(root, padx=10, pady=10)
frame.grid(sticky="nsew")

# Row 0: Input file selection.
tk.Label(frame, text="Select your mbox file:").grid(row=0, column=0, sticky="w")
file_entry = tk.Entry(frame, textvariable=selected_file_var, width=50)
file_entry.grid(row=0, column=1, padx=(0, 10))
tk.Button(frame, text="Browse", command=browse_file).grid(row=0, column=2)

# Row 1: Sender email.
tk.Label(frame, text="Enter your sender email address:").grid(row=1, column=0, sticky="w", pady=(10, 0))
email_entry = tk.Entry(frame, textvariable=sender_email_var, width=50)
email_entry.grid(row=1, column=1, columnspan=2, padx=(0, 10), pady=(10, 0))

# Row 2: Checkbox for filtering.
tk.Checkbutton(frame,
               text="Only include emails sent by me (exclude others even in conversation)",
               variable=filter_non_sent_var).grid(row=2, column=0, columnspan=3, pady=(10, 0), sticky="w")

# Row 3: Output folder selection.
tk.Label(frame, text="Select output folder:").grid(row=3, column=0, sticky="w", pady=(10, 0))
output_folder_entry = tk.Entry(frame, textvariable=output_folder_var, width=50)
output_folder_entry.grid(row=3, column=1, padx=(0, 10), pady=(10, 0))
tk.Button(frame, text="Browse Folder", command=browse_output_folder).grid(row=3, column=2, pady=(10, 0))

# Row 4: Max words per file.
tk.Label(frame, text="Max words per file:").grid(row=4, column=0, sticky="w", pady=(10, 0))
max_words_entry = tk.Entry(frame, textvariable=max_words_var, width=20)
max_words_entry.grid(row=4, column=1, sticky="w", padx=(0, 10), pady=(10, 0))

# Row 5: Max size (MB) per file.
tk.Label(frame, text="Max size (MB) per file:").grid(row=5, column=0, sticky="w", pady=(10, 0))
max_mb_entry = tk.Entry(frame, textvariable=max_mb_var, width=20)
max_mb_entry.grid(row=5, column=1, sticky="w", padx=(0, 10), pady=(10, 0))

# Row 6: Convert button.
convert_button = tk.Button(frame, text="Convert", command=start_conversion_thread)
convert_button.grid(row=6, column=0, columnspan=3, pady=(10, 0))

# Row 7: Progress bar.
progress_bar = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate")
progress_bar.grid(row=7, column=0, columnspan=3, pady=(10, 0))

# Row 8: Status label.
status_label = tk.Label(frame, text="Ready to convert")
status_label.grid(row=8, column=0, columnspan=3, pady=(10, 0))

# Row 9: Log area.
log_text = ScrolledText(frame, width=80, height=10, state="disabled")
log_text.grid(row=9, column=0, columnspan=3, pady=(10, 0))

# Configure grid weights for proper resizing.
root.grid_rowconfigure(9, weight=1)
root.grid_columnconfigure(0, weight=1)

# Set closing protocol to save settings.
root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
