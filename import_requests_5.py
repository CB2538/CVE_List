import os
import requests
import pandas as pd
import json

def extract_project_name(project_url):
    """Extract the project name from the project URL."""
    try:
        # Split the URL and take the last part as the project name
        # Assuming the format is always 'https://github.com/ANY_VARIABLE/PROJECT_NAME'
        return project_url.split('/')[-1]
    except Exception as e:
        print(f"Error extracting project name: {e}")
        return "Unknown Project"

def get_cve_details(api_key, cve_entries, input_file):
    # Headers to include the API key
    headers = {'apiKey': api_key}
    
    # Counters and storage for summary
    total_cves = len(cve_entries)
    successful_cves = 0
    failed_cves = []

    # List to store CVE data for CSV export
    cve_data_list = []

    for entry in cve_entries:
        cve_id = entry['cve']
        project_url = entry['project']

        # API endpoint with the CVE number dynamically inserted
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

        # Sending a GET request to the NVD API
        response = requests.get(url, headers=headers)

        # Check if the response was successful
        if response.status_code == 200:
            try:
                data = response.json()  # Parse JSON from the response
                # Navigate through the JSON data to find the details
                vulnerabilities = data.get('vulnerabilities', [])

                if vulnerabilities:
                    # Extract CVE details if available
                    cve_name = vulnerabilities[0]['cve']['id']
                    metrics = vulnerabilities[0]['cve'].get('metrics', {})
                    cvss_metrics = metrics.get('cvssMetricV31', [])

                    if cvss_metrics:
                        cvss_data = cvss_metrics[0]['cvssData']
                        base_score = cvss_data['baseScore']
                        base_severity = cvss_data['baseSeverity']
                    else:
                        base_score = "N/A"
                        base_severity = "N/A"

                    descriptions = vulnerabilities[0]['cve'].get('descriptions', [])
                    description = descriptions[0]['value'] if descriptions else "No description available"

                    # Get the project name for the current CVE
                    project_name = extract_project_name(project_url)

                    # Add CVE data to list for CSV export
                    cve_data_list.append({
                        'CVE Name': cve_name,
                        'Base Score': base_score,
                        'Base Severity': base_severity,
                        'Description': description,
                        'Project': project_name
                    })

                    # Print CVE details
                    print(f"CVE Name: {cve_name}")
                    print(f"Base Score: {base_score}")
                    print(f"Base Severity: {base_severity}")
                    print(f"Description: {description}")
                    print(f"Project: {project_name}")
                    print("\n" + "-"*40 + "\n")

                    # Increment the counter for successful retrievals
                    successful_cves += 1

                else:
                    error_message = "No vulnerability data found"
                    failed_cves.append((cve_id, error_message))
                    print(f"Error accessing data for CVE {cve_id}: {error_message}")

            except (KeyError, IndexError) as e:
                # This will catch errors related to key access or list access issues
                error_message = f"Error accessing data: {str(e)}"
                failed_cves.append((cve_id, error_message))
                print(f"Error accessing data for CVE {cve_id}: {error_message}")

            except json.JSONDecodeError:
                # This will catch decoding errors
                error_message = "Error decoding JSON"
                failed_cves.append((cve_id, error_message))
                print(f"Error decoding JSON for CVE {cve_id}")
                
        else:
            error_message = f"HTTP {response.status_code}"
            failed_cves.append((cve_id, error_message))
            print(f"Failed to fetch data for CVE {cve_id}: {error_message}")

    # Export CVE data to CSV
    if cve_data_list:
        output_file = f"{os.path.splitext(input_file)[0]}_CVEDETAILS_EXPORT.csv"
        df = pd.DataFrame(cve_data_list)

        # Add summary rows to the DataFrame
        summary_data = [
            {'CVE Name': 'Summary', 'Base Score': '', 'Base Severity': '', 'Description': '', 'Project': ''},
            {'CVE Name': 'Total CVEs processed', 'Base Score': total_cves, 'Base Severity': '', 'Description': '', 'Project': ''},
            {'CVE Name': 'Successfully processed CVEs', 'Base Score': successful_cves, 'Base Severity': '', 'Description': '', 'Project': ''},
            {'CVE Name': 'Failed to process CVEs', 'Base Score': len(failed_cves), 'Base Severity': '', 'Description': '', 'Project': ''},
        ]

        # Append failed CVE details to the summary data
        for cve_id, reason in failed_cves:
            summary_data.append({
                'CVE Name': f'Failed CVE ID: {cve_id}',
                'Base Score': '',
                'Base Severity': '',
                'Description': f'Reason: {reason}',
                'Project': ''
            })

        # Convert the summary data to a DataFrame and concatenate it with the CVE data
        summary_df = pd.DataFrame(summary_data)
        final_df = pd.concat([df, summary_df], ignore_index=True)

        # Write to CSV
        final_df.to_csv(output_file, index=False)
        print(f"Exported CVE details and summary to {output_file}")

    # Print summary to console
    print("\nSummary")
    print("="*40)
    print(f"Total CVEs processed: {total_cves}")
    print(f"Successfully processed CVEs: {successful_cves}")
    print(f"Failed to process CVEs: {len(failed_cves)}")
    
    if failed_cves:
        print("\nFailed CVE Details:")
        for cve_id, reason in failed_cves:
            print(f"- CVE ID: {cve_id} - Reason: {reason}")
    print("\n" + "="*40 + "\n")

def read_cve_ids_from_csv(file_path):
    """Read cve IDs and project URLs from a CSV file."""
    try:
        df = pd.read_csv(file_path)
        # Remove duplicates where both cve and project are the same
        unique_entries = df.drop_duplicates(subset=['cve', 'project'])
        cve_entries = unique_entries[['cve', 'project']].dropna().to_dict('records')
        return cve_entries
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except pd.errors.EmptyDataError:
        print("No data found in the CSV file.")
        return []
    except KeyError:
        print("The CSV file does not contain the required columns.")
        return []

# Example usage
if __name__ == "__main__":
    # Fetch the API key from the environment variable
    api_key = os.getenv('NVD_API_KEY')
    
    if not api_key:
        print("Error: API key not found. Please set the NVD_API_KEY environment variable.")
    else:
        input_file = 'TestFileCVEList.csv'  # Updated input file name
        cve_entries = read_cve_ids_from_csv(input_file)
        
        if cve_entries:
            get_cve_details(api_key, cve_entries, input_file)
        else:
            print("No CVE IDs to process.")
