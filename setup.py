import subprocess
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner Setup")
    parser.add_argument('--choice', choices=['gui', 'cli'], help="Specify the setup choice (gui/cli)")
    args = parser.parse_args()

    print("Welcome to the Vulnerability Scanner Setup!")
    
    choice = args.choice
    
    if choice == 'gui':
        print("\nSetting up the web-based GUI...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("\nDependencies installed successfully!")
            print("\nTo run the web GUI, use the following command:")
            print("  python3 scanner.py --web")
        except subprocess.CalledProcessError as e:
            print(f"\nError installing dependencies: {e}")
            print("Please install the dependencies manually by running: pip install -r requirements.txt")
    elif choice == 'cli':
        print("\nTo run the command-line interface, use the following command:")
        print("  python3 scanner.py --target <target_url>")
    else:
        print("\nInvalid choice. Please run the script again and choose either 'gui' or 'cli'.")

if __name__ == "__main__":
    main()
