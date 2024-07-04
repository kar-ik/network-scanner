import os
import subprocess

def update_tool():
    try:
        # Check if git is installed
        subprocess.run(["git", "--version"], check=True)

        # Pull the latest changes from the repository
        subprocess.run(["git", "pull"], check=True)
        print("Tool updated successfully.")
    except subprocess.CalledProcessError as e:
        print("An error occurred while updating the tool:", e)
    except FileNotFoundError:
        print("Git is not installed. Please install Git to use this update feature.")

if __name__ == "__main__":
    update_tool()
