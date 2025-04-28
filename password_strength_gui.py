import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import customtkinter as ctk
from password_strength import PasswordStrengthScorer
import logging
import os
from datetime import datetime
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('password_analyzer.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class PasswordStrengthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Scoring")
        self.root.geometry("800x600")
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize scorer
        try:
            self.scorer = PasswordStrengthScorer()
            logger.info("Password strength scorer initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize password strength scorer: {str(e)}", exc_info=True)
            messagebox.showerror("Error", "Failed to initialize password strength analyzer. Please check the logs.")
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
            text="Password Strength Scoring",
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
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_check.pack(anchor=tk.W, pady=(0, 10))
        
        # Analyze button
        self.analyze_button = ctk.CTkButton(
            self.input_frame,
            text="Analyze Password",
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
            text="Analysis Results",
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
            # Get predictions using the correct method
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
            
            # Get feature analysis
            features = self.scorer.extract_features(password)
            
            # Clear previous results
            self.results_text.delete("0.0", tk.END)
            
            # Display results with modern formatting
            self.results_text.insert("0.0", "Password Strength Analysis\n", "title")
            self.results_text.insert(tk.END, "=" * 30 + "\n\n")
            
            # Random Forest prediction
            self.results_text.insert(tk.END, "Random Forest Model:\n")
            self.results_text.insert(tk.END, f"Strength: {predictions['random_forest']}%\n")
            self.results_text.insert(tk.END, f"Rating: {self.scorer.get_strength_description(predictions['random_forest'])}\n\n")
            
            # SVM prediction
            self.results_text.insert(tk.END, "SVM Model:\n")
            self.results_text.insert(tk.END, f"Strength: {predictions['svm']}%\n")
            self.results_text.insert(tk.END, f"Rating: {self.scorer.get_strength_description(predictions['svm'])}\n\n")
            
            # Ensemble prediction
            self.results_text.insert(tk.END, "Overall Strength:\n")
            self.results_text.insert(tk.END, f"Strength: {predictions['ensemble']}%\n")
            self.results_text.insert(tk.END, f"Rating: {self.scorer.get_strength_description(predictions['ensemble'])}\n\n")
            
            # Feature analysis
            self.results_text.insert(tk.END, "Feature Analysis:\n")
            for feature, value in features.iloc[0].items():
                if feature == 'entropy':
                    # Format entropy to 2 decimal places
                    formatted_value = f"{value:.2f}"
                else:
                    # Format other features as whole numbers
                    formatted_value = f"{int(value)}"
                self.results_text.insert(tk.END, f"• {feature}: {formatted_value}\n")
            
            # Add detailed feedback
            self.results_text.insert(tk.END, "\nDetailed Feedback:\n")
            
            # Check for repeated characters
            repeated_chars = [c for c in set(password) if password.count(c) > 2]
            if repeated_chars:
                self.results_text.insert(tk.END, f"• Avoid repeating characters like '{', '.join(repeated_chars)}'\n")
            
            # Check for sequential characters
            sequences = []
            for i in range(len(password)-2):
                if (ord(password[i+1]) == ord(password[i]) + 1 and 
                    ord(password[i+2]) == ord(password[i]) + 2):
                    sequences.append(password[i:i+3])
            if sequences:
                self.results_text.insert(tk.END, f"• Avoid sequential characters like '{', '.join(sequences)}'\n")
            
            # Check for common patterns
            if re.search(r'123|abc|qwerty|password', password.lower()):
                self.results_text.insert(tk.END, "• Avoid common patterns like '123', 'abc', 'qwerty', or 'password'\n")
            
            # Check for common character substitutions (leetspeak)
            substitutions = {
                '@': 'a', '4': 'a', '3': 'e', '1': 'i', '0': 'o',
                '$': 's', '5': 's', '7': 't', '8': 'b', '9': 'g'
            }
            
            # Create a normalized version of the password
            normalized = password.lower()
            for sub, letter in substitutions.items():
                normalized = normalized.replace(sub, letter)
            
            # Check if the normalized password contains common words
            try:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                dictionary_path = os.path.join(script_dir, 'common-passwords.txt')
                
                if os.path.exists(dictionary_path):
                    with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as file:
                        common_words = [line.strip().lower() for line in file]
                    
                    found_words = []
                    for word in common_words:
                        if word in normalized:
                            found_words.append(word)
                    
                    if found_words:
                        self.results_text.insert(tk.END, f"• Avoid predictable substitutions (e.g., '@' for 'a', '3' for 'e')\n")
                        self.results_text.insert(tk.END, f"  Detected word{'s' if len(found_words) > 1 else ''}: {', '.join(found_words)}\n")
            except Exception as e:
                logger.error(f"Error checking common passwords: {str(e)}", exc_info=True)
            
            # Add recommendations
            self.results_text.insert(tk.END, "\nRecommendations:\n")
            if predictions['ensemble'] < 40:
                self.results_text.insert(tk.END, "• Consider using a longer password\n")
                self.results_text.insert(tk.END, "• Add more special characters\n")
                self.results_text.insert(tk.END, "• Include numbers and mixed case letters\n")
            elif predictions['ensemble'] < 80:
                self.results_text.insert(tk.END, "• Your password is decent, but could be stronger\n")
                self.results_text.insert(tk.END, "• Consider adding more special characters\n")
                self.results_text.insert(tk.END, "• Try to make it longer if possible\n")
                self.results_text.insert(tk.END, "• Avoid using common words or patterns\n")
            else:
                self.results_text.insert(tk.END, "• Excellent password strength!\n")
                self.results_text.insert(tk.END, "• Keep using a mix of characters like this\n")
                self.results_text.insert(tk.END, "• Remember to use different strong passwords for different accounts\n")
                self.results_text.insert(tk.END, "• Consider using a password manager to store it securely\n")
            
            logger.info(f"Password analyzed successfully: {password[:5]}...")
            
        except Exception as e:
            logger.error(f"Error analyzing password: {str(e)}", exc_info=True)
            messagebox.showerror("Error", "An error occurred while analyzing the password. Please check the logs.")

def main():
    root = ctk.CTk()
    app = PasswordStrengthGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 