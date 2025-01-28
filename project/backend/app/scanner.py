import subprocess

def run_nmap_scan(target: str) -> str:
    try:
        result = subprocess.run(
            ["nmap", "-sV", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return result.stdout.decode('utf-8')
    except Exception as e:
        return f"Error: {str(e)}"
