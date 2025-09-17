# crew.py (VulReaper) — Enhanced with individual file tasks and improved reporting
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List, Dict, Any
from crewai_tools import FileReadTool,DirectoryReadTool
import os, json, hashlib
from pathlib import Path
from dotenv import load_dotenv

# ---------- Configuration ----------
load_dotenv()

# Set the target directory via env or default path
TARGET_DIRECTORY = os.getenv('TARGET_DIRECTORY', r"C:\Users\Ashish Yadav\OneDrive\Desktop\my_place")

# Directories to ignore (case-insensitive)
EXCLUDE_DIRS = set(map(str.lower, [
    "node_modules", "venv", ".venv", ".git", "__pycache__", ".pytest_cache",
    "build", "dist", "target", ".mypy_cache", ".tox", ".cache", ".gradle",
]))

# File globs to ignore (binary/heavy artifacts)
EXCLUDE_GLOBS = [
    "*.png","*.jpg","*.jpeg","*.gif","*.bmp","*.ico","*.webp",
    "*.pdf","*.doc","*.docx","*.xls","*.xlsx","*.ppt","*.pptx",
    "*.zip","*.tar","*.gz","*.rar","*.7z",
]

# Include likely code/config extensions; also include no-extension files
INCLUDE_EXTS = set(map(str.lower, """
.py .js .jsx .ts .tsx .java .c .cpp .cc .h .hpp .cs .php .rb .go .rs .swift .kt .kts .scala
.pl .pm .tcl .lua .r .m .mm .sh .bash .zsh .ps1 .psm1 .bat .cmd
.html .htm .xhtml .css .scss .sass .less .ejs .erb .mustache .handlebars .vue .svelte
.json .yaml .yml .xml .config .conf .ini .toml .properties .env
.j2 .jinja .jinja2
.sql
.csproj .sln .vcxproj .xcodeproj .pro .mk .gradle .pom .nuspec
""".split()))

ALWAYS_INCLUDE_FILENAMES = {
    "Makefile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "package-lock.json", "yarn.lock", "Pipfile.lock",
}

OUTPUT_DIR = Path("outputs")
ALL_FILES_JSON = OUTPUT_DIR / "all_code_files.json"
INDIVIDUAL_ANALYSES_DIR = OUTPUT_DIR / "individual_analyses"
ANALYSIS_JSON = OUTPUT_DIR / "comprehensive_vulnerability_analysis.json"
REPORT_MD = OUTPUT_DIR / "exhaustive_security_assessment_report.md"
REPORT_HTML = OUTPUT_DIR / "security_assessment_report.html"


# ---------- Helpers ----------
def _validate_target_dir() -> Path:
    root = Path(TARGET_DIRECTORY).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Target directory does not exist: {root}")
    return root

def _norm(p: Path) -> str:
    # normalize to absolute POSIX-style so the tool can read it reliably
    return str(p.resolve()).replace("\\", "/")

def _should_skip_dir(dirname: str) -> bool:
    return dirname.lower() in EXCLUDE_DIRS

def _matches_any_glob(path: Path, globs: list[str]) -> bool:
    p = str(path)
    return any(path.match(g) or Path(p.lower()).match(g) for g in globs)

def _is_candidate_file(path: Path) -> bool:
    if _matches_any_glob(path, EXCLUDE_GLOBS):
        return False
    if path.name in ALWAYS_INCLUDE_FILENAMES:
        return True
    ext = path.suffix.lower()
    return (ext in INCLUDE_EXTS) or (ext == "")  # allow no-extension (scripts)

def _walk_all_code_files(root: Path) -> list[Dict[str, Any]]:
    results: list[Dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune ignored directories
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        for name in filenames:
            full = Path(dirpath) / name
            if _is_candidate_file(full):
                try:
                    size = full.stat().st_size
                except Exception:
                    size = None
                
                # Generate a unique task ID for each file
                task_id = _generate_file_task_id(full)
                
                results.append({
                    "file_path": _norm(full),
                    "path": _norm(full),
                    "relative_path": str(full.relative_to(root)).replace("\\", "/"),
                    "extension": full.suffix.lower(),
                    "size_bytes": size,
                    "task_id": task_id,
                })
    results.sort(key=lambda x: (x["relative_path"].lower(), x["path"].lower()))
    return results

def _generate_file_task_id(file_path: Path) -> str:
    """Generate a unique, deterministic task ID for a file"""
    # Use relative path to create consistent IDs across runs
    content = str(file_path).lower().replace("\\", "/")
    return f"file_{hashlib.md5(content.encode()).hexdigest()[:12]}"

def _ensure_file_list():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    INDIVIDUAL_ANALYSES_DIR.mkdir(parents=True, exist_ok=True)
    root = _validate_target_dir()
    all_files = _walk_all_code_files(root)
    with ALL_FILES_JSON.open("w", encoding="utf-8") as f:
        json.dump({
            "root": str(root),
            "count": len(all_files),
            "files": all_files,
            "timestamp": str(os.times())
        }, f, ensure_ascii=False, indent=2)
    print(f"🔍 Indexed {len(all_files)} files under {root}. Saved to {ALL_FILES_JSON}")
    return all_files

# ---------- Tools ----------
file_read_tool = FileReadTool()
dir_read_tool = DirectoryReadTool()


@CrewBase
class VulReaper():
    """VulReaper crew for comprehensive vulnerability scanning and security analysis"""

    agents: List[BaseAgent]
    tasks: List[Task]
    _file_analysis_tasks: List[Task] = []
    _all_files: List[Dict[str, Any]] = []

    # Agents
    @agent
    def comprehensive_file_scanner(self) -> Agent:
        return Agent(
            config=self.agents_config['comprehensive_file_scanner'],
            tools=[file_read_tool],
            verbose=True,
            # reasoning=True,
            allow_delegation=False,
        )

    @agent
    def individual_file_analyzer(self) -> Agent:
        return Agent(
            config=self.agents_config['individual_file_analyzer'],
            tools=[file_read_tool],
            max_iter=50,
            verbose=True,
            # reasoning=True,
            allow_delegation=False,
        )

    @agent
    def vulnerability_aggregator(self) -> Agent:
        return Agent(
            config=self.agents_config['vulnerability_aggregator'],
            tools=[dir_read_tool,file_read_tool],
            max_iter=100,
            verbose=True,
            # reasoning=True,
            allow_delegation=False,
        )

    @agent
    def exhaustive_security_reporter(self) -> Agent:
        return Agent(
            config=self.agents_config['exhaustive_security_reporter'],
            tools=[file_read_tool],
            verbose=True,
            # reasoning=True,
            allow_delegation=False,
        )


    # Base Tasks
    @task
    def scan_all_code_files_task(self) -> Task:
        return Task(
            config=self.tasks_config['scan_all_code_files_task'],
            agent=self.comprehensive_file_scanner(),
            output_file=str(ALL_FILES_JSON)
        )

    def create_individual_file_analysis_tasks(self) -> List[Task]:
        """Create individual analysis tasks for each file"""
        if not self._all_files:
            return []
        
        individual_tasks = []
        
        for file_info in self._all_files:
            task_config = {
                'description': f"""
                    Analyze {file_info['relative_path']} for security vulnerabilities.
                    Include code snippets for each finding.
                    File: {file_info['file_path']}
                    Size: {file_info.get('size_bytes', 'Unknown')} bytes
                    Extension: {file_info.get('extension', 'none')}
                    
                    INSTRUCTIONS:
                    1. Read file using FileReadTool with file_path="{file_info['file_path']}"
                    2. Perform line-by-line security analysis
                    3. For each finding, extract 3-15 lines of code as evidence
                    4. Include precise line numbers and remediation
                    5. Output JSON with file_path and findings in the specified format
                """,
                'expected_output': f'''
                {{
                  "file_path": "{file_info['relative_path']}",
                  "findings": [
                    {{
                      "line": 10,
                      "vulnerability": "Description of vulnerability",
                      "code_snippet": "Vulnerable code lines",
                      "recommendation": "Specific fix recommendation"
                    }}
                  ]
                }}''',
            }
            
            task = Task(
                config=task_config,
                agent=self.individual_file_analyzer(),
                output_file=str(INDIVIDUAL_ANALYSES_DIR / f"{file_info['task_id']}_analysis.json")
            )
            individual_tasks.append(task)
        
        return individual_tasks

    @task
    def aggregate_all_vulnerabilities_task(self) -> Task:
        simplified_config = {
            'description': '''
                PURPOSE: Read ALL individual analysis JSON files from outputs/individual_analyses/ 
                and consolidate them into a comprehensive vulnerability database.
                
                INSTRUCTIONS:
                1. Use FileReadTool to read all *_analysis.json files from outputs/individual_analyses/
                2. For each file, extract the findings array
                3. Combine all findings into a single list
                4. Generate basic statistics (count by severity)
                5. Output the consolidated results
                
                ERROR HANDLING:
                - If directory doesn't exist, create empty results
                - If individual files can't be read, skip them and continue
                - Always produce valid JSON output
            ''',
            'expected_output': 'A JSON file containing all findings from individual analysis files with basic statistics.'
        }
        
        return Task(
            config=simplified_config,
            agent=self.vulnerability_aggregator(),
            context=self._file_analysis_tasks,
            output_file=str(ANALYSIS_JSON)
        )

    @task
    def generate_markdown_report_task(self) -> Task:
        return Task(
            config=self.tasks_config['generate_markdown_report_task'],
            agent=self.exhaustive_security_reporter(),
            context=[self.aggregate_all_vulnerabilities_task()],
            output_file=str(REPORT_MD)
        )


    @crew
    def crew(self) -> Crew:
        """Creates the VulReaper comprehensive security scanning crew with individual file tasks"""
        # Build the complete file list *deterministically* before any agent runs
        self._all_files = _ensure_file_list()
        
        # Create individual file analysis tasks
        self._file_analysis_tasks = self.create_individual_file_analysis_tasks()
        
        print(f"🚀 Created {len(self._file_analysis_tasks)} individual file analysis tasks")
        
        # Build the complete task list
        all_tasks = [
            self.scan_all_code_files_task(),
            *self._file_analysis_tasks,
            self.aggregate_all_vulnerabilities_task(),
            self.generate_markdown_report_task()
        ]
        
        # Get all agents
        all_agents = [
            self.comprehensive_file_scanner(),
            self.individual_file_analyzer(),
            self.vulnerability_aggregator(),
            self.exhaustive_security_reporter()
        ]
        
        return Crew(
            agents=all_agents,
            tasks=all_tasks,
            process=Process.sequential,
            verbose=True,
            # planning=True
        )