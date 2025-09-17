# main.py — Enhanced launcher for VulReaper with individual file analysis
#!/usr/bin/env python
import warnings
import time
from datetime import datetime
from pathlib import Path
from .crew import VulReaper  # crew.py in the same directory

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

def print_banner():
    """Print VulReaper banner with enhanced capabilities"""
    print("=" * 80)
    print("🔍 VulReaper v2.0 - Enhanced Comprehensive Security Analysis")
    print("=" * 80)
    print("🚀 NEW FEATURES:")
    print("   • Individual file analysis tasks for maximum precision")
    print("   • Cross-file vulnerability correlation and attack chains")
    print("   • Interactive HTML reports with advanced filtering")
    print("   • Enhanced coverage tracking and gap analysis")
    print("   • Proof-of-concept generation for verified vulnerabilities")
    print("=" * 80)

def print_progress_summary(file_count: int):
    """Print analysis progress summary"""
    print(f"📊 ANALYSIS SCOPE:")
    print(f"   • Total files to analyze: {file_count}")
    print(f"   • Individual analysis tasks: {file_count}")
    print(f"   • Expected output files: {file_count + 4}")  # individual + 4 summary files
    print(f"   • Estimated analysis time: {file_count * 0.5:.1f} - {file_count * 2:.1f} minutes")
    print("-" * 70)

def validate_outputs():
    """Validate that all expected output files were created"""
    output_dir = Path("outputs")
    expected_files = [
        "all_code_files.json",
        "comprehensive_vulnerability_analysis.json", 
        "exhaustive_security_assessment_report.md",
        "security_assessment_report.html"
    ]
    
    print("🔍 VALIDATING OUTPUTS:")
    all_created = True
    
    for filename in expected_files:
        filepath = output_dir / filename
        if filepath.exists():
            size = filepath.stat().st_size
            print(f"   ✅ {filename} ({size:,} bytes)")
        else:
            print(f"   ❌ {filename} (MISSING)")
            all_created = False
    
    # Check individual analysis files
    individual_dir = output_dir / "individual_analyses"
    if individual_dir.exists():
        individual_files = list(individual_dir.glob("*_analysis.json"))
        print(f"   ✅ Individual analyses: {len(individual_files)} files")
    else:
        print(f"   ❌ Individual analyses directory (MISSING)")
        all_created = False
    
    return all_created

def print_completion_summary(start_time: float, success: bool):
    """Print completion summary with timing and output information"""
    duration = time.time() - start_time
    duration_str = f"{duration:.1f} seconds" if duration < 60 else f"{duration/60:.1f} minutes"
    
    print("=" * 70)
    if success:
        print("✅ COMPREHENSIVE ANALYSIS COMPLETED SUCCESSFULLY!")
    else:
        print("⚠️  ANALYSIS COMPLETED WITH ISSUES!")
    
    print(f"⏰ Total execution time: {duration_str}")
    print(f"📅 Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    print("📄 OUTPUT FILES GENERATED:")
    print("   📋 outputs/all_code_files.json")
    print("      └── Complete file inventory with task assignments")
    print("   📁 outputs/individual_analyses/")
    print("      └── Individual vulnerability analysis for each file")
    print("   🔍 outputs/comprehensive_vulnerability_analysis.json")
    print("      └── Consolidated findings with attack chains and statistics")
    print("   📝 outputs/exhaustive_security_assessment_report.md") 
    print("      └── Professional Markdown report for technical teams")
    print("   🌐 outputs/security_assessment_report.html")
    print("      └── Interactive web report with filtering and charts")
    print("=" * 70)

def run():
    """Enhanced main execution function with detailed progress tracking"""
    start_time = time.time()
    
    print_banner()
    print(f"⏰ Analysis started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Initialize VulReaper
        print("🔧 Initializing VulReaper crew...")
        vul_reaper = VulReaper()
        
        # Get file count for progress tracking (this triggers file indexing)
        print("📁 Indexing target directory...")
        # The file list is created during crew initialization
        
        # Load file count from the generated index
        from pathlib import Path
        import json
        
        all_files_json = Path("outputs/all_code_files.json")
        if all_files_json.exists():
            with open(all_files_json, 'r', encoding='utf-8') as f:
                file_data = json.load(f)
                file_count = file_data.get('count', 0)
                print_progress_summary(file_count)
        else:
            print("⚠️  Could not determine file count - proceeding with analysis...")
        
        # Execute the crew
        print("🚀 Starting comprehensive security analysis...")
        print("   Phase 1: File inventory and task creation")
        print("   Phase 2: Individual file analysis (parallel processing)")
        print("   Phase 3: Vulnerability aggregation and correlation")
        print("   Phase 4: Report generation (Markdown + HTML)")
        print("-" * 70)

        crew_instance = vul_reaper.crew()
        
        result = crew_instance.kickoff()
        
        # Validate outputs
        print("-" * 70)
        outputs_valid = validate_outputs()
        
        # Print completion summary
        print_completion_summary(start_time, outputs_valid)
        
        if outputs_valid:
            print("🎯 NEXT STEPS:")
            print("   1. Review the HTML report for interactive analysis")
            print("   2. Share the Markdown report with technical teams") 
            print("   3. Prioritize Critical and High severity findings")
            print("   4. Begin remediation following the provided roadmap")
            print("   5. Re-run analysis after fixes to validate improvements")
        else:
            print("⚠️  Some output files are missing. Check logs for errors.")
            
        return result
        
    except KeyboardInterrupt:
        duration = time.time() - start_time
        print(f"\n⏹️  Analysis interrupted by user after {duration:.1f} seconds")
        print("   Partial results may be available in outputs/ directory")
        return None
        
    except Exception as e:
        duration = time.time() - start_time
        print(f"\n❌ ANALYSIS FAILED after {duration:.1f} seconds")
        print(f"   Error: {str(e)}")
        print("   Check logs and file permissions")
        print("   Ensure target directory is accessible and readable")
        raise

def main():
    """Entry point with error handling"""
    try:
        return run()
    except Exception as e:
        print(f"\n💥 FATAL ERROR: {e}")
        print("\n🔧 TROUBLESHOOTING TIPS:")
        print("   • Verify target directory exists and is readable")
        print("   • Check available disk space for output files")
        print("   • Ensure Python has write permissions to outputs/ directory")
        print("   • Review .env file for correct TARGET_DIRECTORY setting")
        print("   • Try running with elevated permissions if needed")
        return None

if __name__ == "__main__":
    main()