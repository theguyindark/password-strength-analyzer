import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import customtkinter as ctk
from password_strength import PasswordStrengthScorer
import logging
import os
from datetime import datetime
import re

logging.basicConfig(
    level=logging.DEBUG, # Ensure GUI also logs at DEBUG to show sensitive info
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('insecure_password_analyzer.log'), # Log to the same insecure file
        logging.StreamHandler() 
    ]
)

logger = logging.getLogger(__name__)

class PasswordStrengthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Scoring (Insecure Version)") # Indicate it's insecure
        self.root.geometry("800x600")

        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Initialize scorer
        try:
            self.scorer = PasswordStrengthScorer()
            logger.info("Password strength scorer initialized successfully (potentially insecurely).")
        except Exception as e:
            logger.error(f"Failed to initialize password strength scorer (insecure loading): {str(e)}", exc_info=True)
            messagebox.showerror("Initialization Error (Insecure)", f"Failed to initialize password strength analyzer. Details: {str(e)}. Please check 'insecure_password_analyzer.log'.")
            root.destroy()
            return

        self.create_widgets()

    def create_widgets(self):
        # Main container
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        self.title_label = ctk.CTkLabel(
            self.main_frame,
            text="Password Strength Scoring (Intentionally Insecure)", # Indicate insecurity
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.title_label.pack(pady=20)

        # Input frame
        self.input_frame = ctk.CTkFrame(self.main_frame)
        self.input_frame.pack(fill=tk.X, padx=20, pady=10)

        # Password input
        self.password_label = ctk.CTkLabel(
            self.input_frame,
            text="Enter Password:",
            font=ctk.CTkFont(size=14)
        )
        self.password_label.pack(anchor=tk.W, pady=(0, 5))

        self.password_entry = ctk.CTkEntry(
            self.input_frame,
            width=400,
            height=40,
            font=ctk.CTkFont(size=14),
            show="•"
        )
        self.password_entry.pack(fill=tk.X, pady=(0, 10))

        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = ctk.CTkCheckBox(
            self.input_frame,
            text="Show Password (Use with Caution)", # Add warning
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_check.pack(anchor=tk.W, pady=(0, 10))

        # Analyze button
        self.analyze_button = ctk.CTkButton(
            self.input_frame,
            text="Analyze Password (Insecurely)", # Indicate insecurity
            command=self.analyze_password,
            width=200,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.analyze_button.pack(pady=10)

        # Strength bar frame
        self.strength_frame = ctk.CTkFrame(self.main_frame)
        self.strength_frame.pack(fill=tk.X, padx=20, pady=10)

        # Strength label
        self.strength_label = ctk.CTkLabel(
            self.strength_frame,
            text="Password Strength:",
            font=ctk.CTkFont(size=14)
        )
        self.strength_label.pack(anchor=tk.W, pady=(0, 5))

        # Strength bar
        self.strength_bar = ctk.CTkProgressBar(
            self.strength_frame,
            width=400,
            height=20
        )
        self.strength_bar.pack(fill=tk.X, pady=(0, 5))
        self.strength_bar.set(0)  # Initialize at 0

        # Strength rating label
        self.strength_rating_label = ctk.CTkLabel(
            self.strength_frame,
            text="",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.strength_rating_label.pack(pady=(0, 5))

        # Results frame
        self.results_frame = ctk.CTkFrame(self.main_frame)
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Results title
        self.results_label = ctk.CTkLabel(
            self.results_frame,
            text="Analysis Results (Potentially Inaccurate/Insecure)", # Indicate potential issues
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.results_label.pack(pady=10)

        # Results text
        self.results_text = ctk.CTkTextbox(
            self.results_frame,
            width=600,
            height=200,
            font=ctk.CTkFont(size=14)
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Theme switcher
        self.theme_switch = ctk.CTkSwitch(
            self.main_frame,
            text="Light Mode",
            command=self.toggle_theme
        )
        self.theme_switch.pack(pady=10)

        self.show_logs_button = ctk.CTkButton(
            self.main_frame,
            text="Show Insecure Logs",
            command=self.show_insecure_logs,
            width=200,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.show_logs_button.pack(pady=10)


    def toggle_theme(self):
        if self.theme_switch.get():
            ctk.set_appearance_mode("light")
        else:
            ctk.set_appearance_mode("dark")

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="•")

    def analyze_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to analyze.")
            return

        try:
            predictions = self.scorer.predict_strength(password)

            # Update strength bar
            strength = predictions['ensemble'] / 100  # Convert to 0-1 range
            self.strength_bar.set(strength)

            # Get strength rating and update label
            strength_rating = self.scorer.get_strength_description(predictions['ensemble'])
            self.strength_rating_label.configure(text=strength_rating)

            # Set color based on strength
            if predictions['ensemble'] < 40:
                self.strength_bar.configure(progress_color="red")
                self.strength_rating_label.configure(text_color="red")
            elif predictions['ensemble'] < 80:
                self.strength_bar.configure(progress_color="orange")
                self.strength_rating_label.configure(text_color="orange")
            else:
                self.strength_bar.configure(progress_color="green")
                self.strength_rating_label.configure(text_color="green")

            # Get feature analysis using the potentially insecure method
            features = self.scorer.extract_features(password)

            # Clear previous results
            self.results_text.delete("0.0", tk.END)

            # Display results with modern formatting
            self.results_text.insert("0.0", "Password Strength Analysis (Potentially Insecure)\n", "title") # Indicate insecurity
            self.results_text.insert(tk.END, "=" * 30 + "\n\n")

            # Display predictions
            self.results_text.insert(tk.END, "Model Predictions:\n")
            self.results_text.insert(tk.END, f"• Random Forest: {predictions['random_forest']}% ({self.scorer.get_strength_description(predictions['random_forest'])})\n")
            self.results_text.insert(tk.END, f"• SVM: {predictions['svm']}% ({self.scorer.get_strength_description(predictions['svm'])})\n")
            self.results_text.insert(tk.END, f"• Overall Ensemble: {predictions['ensemble']}% ({self.scorer.get_strength_description(predictions['ensemble'])})\n\n")

            # Feature analysis
            self.results_text.insert(tk.END, "Feature Analysis:\n")
            for feature, value in features.iloc[0].items():
                if feature == 'entropy':
                    formatted_value = f"{value:.2f}"
                else:
                    formatted_value = f"{int(value)}"
                self.results_text.insert(tk.END, f"• {feature}: {formatted_value}\n")

            self.results_text.insert(tk.END, "\nDetailed Feedback (Based on Limited Checks):\n")

            # Check for repeated characters (using simple check from library)
            if self.scorer.detect_pattern(password) == 1: # Re-using the simple pattern check
                 self.results_text.insert(tk.END, "• Simple repeated characters or sequences detected.\n") # Less specific feedback

            # Check for common patterns (using simple regex)
            if re.search(r'123|abc|qwerty|password', password.lower()):
                self.results_text.insert(tk.END, "• Avoid common patterns like '123', 'abc', 'qwerty', or 'password'\n")

            try:
                # Re-using the potentially insecure dictionary check from the scorer
                if self.scorer.detect_dictionary_words(password) == 1:
                     self.results_text.insert(tk.END, "• Avoid predictable substitutions (e.g., '@' for 'a', '3' for 'e') or dictionary words.\n") # Less specific feedback
            except Exception as e:
                self.results_text.insert(tk.END, f"• Warning: Dictionary check failed ({str(e)}). Analysis may be incomplete.\n") # VULNERABILITY A09: Exposing internal error details

            self.results_text.insert(tk.END, "\nRecommendations (Generic):\n")
            if predictions['ensemble'] < 40:
                self.results_text.insert(tk.END, "• This password is very weak. Choose a much stronger one.\n")
            elif predictions['ensemble'] < 80:
                self.results_text.insert(tk.END, "• This password is only moderately strong. Consider making it longer and more complex.\n")
            else:
                self.results_text.insert(tk.END, "• This password seems strong based on current checks, but always use unique passwords and a password manager.\n")


            logger.info(f"Password analysis attempted for: {password[:5]}...")
            logger.debug(f"Full analysis results for {password}: {predictions}")

        except Exception as e:
            logger.error(f"Error analyzing password in GUI: {str(e)} for password: {password}", exc_info=True)
            messagebox.showerror("Analysis Error (Insecure)", f"An error occurred while analyzing the password. Details: {str(e)}. Please check 'insecure_password_analyzer.log'.")

    def show_insecure_logs(self):
        """Displays the content of the insecure log file in a new window."""
        log_file_path = 'insecure_password_analyzer.log'
        if not os.path.exists(log_file_path):
            messagebox.showinfo("Log File", "Log file does not exist yet.")
            return

        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                log_content = f.read()

            log_window = tk.Toplevel(self.root)
            log_window.title("Insecure Application Logs")
            log_window.geometry("600x400")

            log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
            log_text.pack(expand=True, fill=tk.BOTH)

            log_text.insert(tk.END, log_content)
            log_text.configure(state='disabled') # Make it read-only

        except Exception as e:
            logger.error(f"Error reading log file: {str(e)}", exc_info=True)
            messagebox.showerror("Log Error (Insecure)", f"Could not read log file. Details: {str(e)}")


def main():
    root = ctk.CTk()
    app = PasswordStrengthGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
