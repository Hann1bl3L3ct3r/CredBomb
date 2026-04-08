import subprocess


def check_nfs(ip, timeout=10):
    """Check for world-exported NFS shares using showmount."""
    try:
        result = subprocess.run(
            ["showmount", "-e", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        output = result.stdout.decode(errors="ignore").strip()

        if not output or "no exports" in output.lower():
            return None

        # Parse showmount output: "/share  (everyone)" or "/share  *" or "/share  0.0.0.0/0"
        exports = []
        world_accessible = []
        for line in output.splitlines()[1:]:  # Skip header line
            line = line.strip()
            if not line:
                continue
            exports.append(line)

            # Check for world-accessible indicators
            lower = line.lower()
            if "*" in lower or "everyone" in lower or "0.0.0.0/0" in lower or "(everyone)" in lower:
                share_path = line.split()[0] if line.split() else line
                world_accessible.append(share_path)

        if exports:
            result_dict = {
                "service": "NFS",
                "issue": "NFS exports exposed",
                "exports": exports,
            }
            if world_accessible:
                result_dict["issue"] = "World-accessible NFS exports found"
                result_dict["world_accessible"] = world_accessible
            return result_dict

    except FileNotFoundError:
        # showmount not installed
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

    return None
