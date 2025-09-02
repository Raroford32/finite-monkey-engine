import argparse
import ast
import os
import sys
import time
from ai_engine import *
from tree_sitter_parsing import TreeSitterProjectAudit as ProjectAudit
from dataset_manager import load_dataset, Project
from planning.planning import Planning
from sqlalchemy import create_engine
from dao import CacheManager, ProjectTaskMgr
import os
import pandas as pd
from openpyxl import Workbook,load_workbook
from openpyxl.utils.dataframe import dataframe_to_rows
from res_processor.res_processor import ResProcessor
from agentic import Orchestrator, InvariantMiner

import dotenv
dotenv.load_dotenv()

# Enhanced logging system for exploit discovery
from logging_config import setup_logging, get_logger, log_section_start, log_section_end, log_step, log_error, log_warning, log_success, log_data_info



def scan_project(project, db_engine):
    """
    Advanced exploit discovery scanner for complex vulnerability detection
    Focuses on real-world permissionless and novel complex exploit discovery
    """
    logger = get_logger("scan_project")
    scan_start_time = time.time()
    
    log_section_start(logger, "Advanced Exploit Discovery Scan", f"Project ID: {project.id}, Path: {project.path}")
    
    # 1. parsing projects with enhanced exploit detection focus
    log_step(logger, "Tree-sitter parsing for exploit discovery", f"Project path: {project.path}")
    parsing_start = time.time()
    
    project_audit = ProjectAudit(project.id, project.path, db_engine)
    project_audit.parse()
    
    parsing_duration = time.time() - parsing_start
    log_success(logger, "Project parsing completed", f"Duration: {parsing_duration:.2f}s")
    log_data_info(logger, "Functions parsed for analysis", len(project_audit.functions_to_check))
    log_data_info(logger, "Call trees constructed", len(project_audit.call_trees))
    log_data_info(logger, "Call graphs analyzed", len(project_audit.call_graphs))
    
    # 1.5 Initialize RAG processor for advanced context understanding
    log_step(logger, "Initializing RAG processor for exploit context")
    rag_processor = None
    try:
        from context.rag_processor import RAGProcessor
        rag_start = time.time()
        
        # Pass project_audit object containing functions, functions_to_check, chunks
        rag_processor = RAGProcessor(
            project_audit, 
            "./src/codebaseQA/lancedb", 
            project.id
        )
        
        rag_duration = time.time() - rag_start
        log_success(logger, "RAG processor initialization completed", f"Duration: {rag_duration:.2f}s")
        log_data_info(logger, "Tree-sitter based functions for RAG", len(project_audit.functions_to_check))
        log_data_info(logger, "Document chunks for RAG", len(project_audit.chunks))
        log_data_info(logger, "Call trees for relationship RAG", len(project_audit.call_trees))
        log_data_info(logger, "Call graph integration", len(project_audit.call_graphs))
        
        # Display call graph statistics
        if project_audit.call_graphs:
            call_graph_stats = project_audit.get_call_graph_statistics()
            log_data_info(logger, "Call Graph statistics", call_graph_stats)
        
    except ImportError as e:
        log_warning(logger, "RAG processor unavailable, using simplified functionality")
        print(e)
        logger.debug(f"ImportError details: {e}")
    except Exception as e:
        log_error(logger, "RAG processor initialization failed", e)
        rag_processor = None
    
    
    # 2. planning & scanning - direct use of project_audit for exploit discovery
    log_step(logger, "Creating task manager for exploit analysis")
    project_taskmgr = ProjectTaskMgr(project.id, db_engine) 
    log_success(logger, "Task manager created successfully")
    
    # Create planning processor with direct project_audit integration
    log_step(logger, "Creating planning processor for complex exploit patterns")
    planning = Planning(project_audit, project_taskmgr)
    log_success(logger, "Planning processor created successfully")
    
    # Initialize planning RAG functionality if available
    if rag_processor:
        log_step(logger, "Initializing planning RAG for advanced exploit detection")
        planning.initialize_rag_processor("./src/codebaseQA/lancedb", project.id)
        log_success(logger, "Planning RAG functionality initialized")
    
    # Create AI engine for advanced vulnerability analysis
    log_step(logger, "Creating AI engine for exploit discovery")
    lancedb_table = rag_processor.db if rag_processor else None
    lancedb_table_name = rag_processor.table_name if rag_processor else f"lancedb_{project.id}"
    logger.info(f"LanceDB table name: {lancedb_table_name}")
    
    engine = AiEngine(planning, project_taskmgr, lancedb_table, lancedb_table_name, project_audit)
    log_success(logger, "AI engine created successfully")
    
    # Execute planning and scanning with exploit focus
    log_step(logger, "Executing advanced exploit planning")
    planning_start = time.time()
    engine.do_planning()
    planning_duration = time.time() - planning_start
    log_success(logger, "Exploit planning completed", f"Duration: {planning_duration:.2f}s")
    
    log_step(logger, "Executing vulnerability scanning (Reasoning)")
    scan_start = time.time()
    engine.do_scan()
    scan_duration = time.time() - scan_start
    log_success(logger, "Vulnerability scanning (Reasoning) completed", f"Duration: {scan_duration:.2f}s")
    
    # Perform deduplication after reasoning and before validation
    log_step(logger, "Post-reasoning deduplication processing")
    dedup_start = time.time()
    ResProcessor.perform_post_reasoning_deduplication(project.id, db_engine, logger)
    dedup_duration = time.time() - dedup_start
    log_success(logger, "Post-reasoning deduplication completed", f"Duration: {dedup_duration:.2f}s")
    
    total_scan_duration = time.time() - scan_start_time
    log_section_end(logger, "Advanced Exploit Discovery Scan", total_scan_duration)

    return lancedb_table, lancedb_table_name, project_audit

def check_function_vul(engine, lancedb, lance_table_name, project_audit):
    """Execute vulnerability validation with direct project_audit data"""
    logger = get_logger("check_function_vul")
    check_start_time = time.time()
    
    log_section_start(logger, "Vulnerability Validation", f"Project ID: {project_audit.project_id}")
    
    log_step(logger, "Creating project task manager")
    project_taskmgr = ProjectTaskMgr(project_audit.project_id, engine)
    log_success(logger, "Project task manager created successfully")
    
    # Directly use project_audit to create vulnerability checker
    log_step(logger, "Initializing vulnerability checker")
    from validating import VulnerabilityChecker
    checker = VulnerabilityChecker(project_audit, lancedb, lance_table_name)
    log_success(logger, "Vulnerability checker initialized successfully")
    
    # Execute vulnerability validation
    log_step(logger, "Executing vulnerability validation")
    validation_start = time.time()
    checker.check_function_vul(project_taskmgr)
    validation_duration = time.time() - validation_start
    log_success(logger, "Vulnerability validation completed", f"Duration: {validation_duration:.2f}s")
    
    total_check_duration = time.time() - check_start_time
    log_section_end(logger, "Vulnerability Validation", total_check_duration)


def parse_arguments():
    """Parse command line arguments for exploit discovery"""
    parser = argparse.ArgumentParser(
        description='Finite Monkey Engine v2.0 - Advanced AI-Powered Exploit Discovery Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a project by providing just the path
  python src/main.py --path /path/to/your/project
  
  # Generate report from existing scan results
  python src/main.py --generate-report --project-id my_project
  
  # Direct Excel generation mode
  python src/main.py --mode direct_excel --project-id pebble
        """)
    
    parser.add_argument(
        '--path', 
        type=str, 
        help='Path to the project directory for exploit discovery analysis'
    )
    
    parser.add_argument(
        '--project-id', 
        type=str, 
        help='Project ID for analysis (auto-generated from path if not provided)'
    )
    
    parser.add_argument(
        '--mode', 
        choices=['test', 'direct_excel', 'exploit_discovery'], 
        default='exploit_discovery',
        help='Operation mode (default: exploit_discovery)'
    )
    
    parser.add_argument(
        '--output', 
        type=str, 
        default='./exploit_analysis_report.xlsx',
        help='Output file path for the analysis report'
    )
    
    parser.add_argument(
        '--generate-report',
        action='store_true',
        help='Generate report from existing analysis data'
    )
    
    parser.add_argument(
        '--scan-mode',
        choices=['PURE_SCAN', 'COMMON_PROJECT', 'CHECKLIST', 'COMMON_PROJECT_FINE_GRAINED'],
        default='COMMON_PROJECT_FINE_GRAINED',
        help='Vulnerability scanning mode (default: COMMON_PROJECT_FINE_GRAINED)'
    )
    
    return parser.parse_args()

def create_project_from_path(project_path, project_id=None):
    """Create a project configuration from a path without requiring datasets.json"""
    if not os.path.exists(project_path):
        raise ValueError(f"Project path does not exist: {project_path}")
    
    if not project_id:
        # Auto-generate project ID from path
        project_id = os.path.basename(os.path.abspath(project_path))
        # Clean project ID for database compatibility
        project_id = ''.join(c for c in project_id if c.isalnum() or c in ['_', '-']).lower()
    
    # Create a project configuration similar to datasets.json format
    project_config = {
        'path': project_path,
        'base_path': '',  # Empty since path is already absolute
        'files': [],
        'functions': [],
        'exclude_in_planning': 'false',
        'exclude_directory': []
    }
    
    return Project(project_id, project_config)
if __name__ == '__main__':
    # Parse command line arguments
    args = parse_arguments()
    
    # Initialize enhanced logging system for exploit discovery
    log_file_path = setup_logging()
    main_logger = get_logger("main")
    main_start_time = time.time()
    
    main_logger.info("🎯 Finite Monkey Engine v2.0 - Advanced Exploit Discovery Platform")
    main_logger.info(f"   Python version: {sys.version}")
    main_logger.info(f"   Working directory: {os.getcwd()}")
    main_logger.info(f"   Environment variables loaded")
    main_logger.info(f"   Operation mode: {args.mode}")

    # Initialize database connection
    log_step(main_logger, "Initializing database connection")
    db_url_from = os.environ.get("DATABASE_URL")
    if not db_url_from:
        log_error(main_logger, "DATABASE_URL environment variable not set")
        sys.exit(1)
    main_logger.info(f"Database URL: {db_url_from}")
    engine = create_engine(db_url_from)
    log_success(main_logger, "Database connection established successfully")

    if args.mode == 'direct_excel':
        log_section_start(main_logger, "Direct Excel Generation Mode")
        
        start_time = time.time()
        
        # Use provided project ID or default
        project_id = args.project_id or 'pebble'
        main_logger.info(f"Target project ID: {project_id}")
        
        # Generate Excel report directly
        log_step(main_logger, "Generating Excel report using ResProcessor")
        excel_start = time.time()
        ResProcessor.generate_excel(args.output, project_id, engine)
        excel_duration = time.time() - excel_start
        log_success(main_logger, "Excel report generated successfully", f"Duration: {excel_duration:.2f}s, File: {args.output}")
        
        total_duration = time.time() - start_time
        log_section_end(main_logger, "Direct Excel Generation Mode", total_duration)
        
    elif args.generate_report:
        log_section_start(main_logger, "Report Generation Mode")
        
        if not args.project_id:
            log_error(main_logger, "Project ID required for report generation")
            sys.exit(1)
            
        start_time = time.time()
        
        log_step(main_logger, "Generating comprehensive exploit analysis report")
        excel_start = time.time()
        ResProcessor.generate_excel(args.output, args.project_id, engine)
        excel_duration = time.time() - excel_start
        log_success(main_logger, "Exploit analysis report generated", f"Duration: {excel_duration:.2f}s, File: {args.output}")
        
        total_duration = time.time() - start_time
        log_section_end(main_logger, "Report Generation Mode", total_duration)
        
    else:  # exploit_discovery or test mode
        log_section_start(main_logger, "Advanced Exploit Discovery Mode")
        
        start_time = time.time()
        
        # Determine project source
        if args.path:
            # Create project from provided path
            main_logger.info(f"Creating project from path: {args.path}")
            try:
                project = create_project_from_path(args.path, args.project_id)
                log_success(main_logger, "Project created from path", f"Project ID: {project.id}")
            except ValueError as e:
                log_error(main_logger, str(e))
                sys.exit(1)
        else:
            # Load from dataset (legacy mode)
            log_step(main_logger, "Loading dataset configuration")
            dataset_base = "./src/dataset/agent-v1-c4"
            main_logger.info(f"Dataset path: {dataset_base}")
            projects = load_dataset(dataset_base)
            log_success(main_logger, "Dataset loaded successfully", f"Found {len(projects)} projects")
     
            # Use provided project ID or default
            project_id = args.project_id or 'pebble'
            if project_id not in projects:
                log_error(main_logger, f"Project ID '{project_id}' not found in dataset")
                available_projects = list(projects.keys())[:10]  # Show first 10
                main_logger.info(f"Available projects: {available_projects}")
                sys.exit(1)
                
            main_logger.info(f"Target project ID: {project_id}")
            project = Project(project_id, projects[project_id])
            log_success(main_logger, "Project object created successfully")
        
        # Check scanning mode from args or environment
        scan_mode = args.scan_mode or os.getenv("SCAN_MODE", "COMMON_PROJECT_FINE_GRAINED")
        main_logger.info(f"Scanning mode: {scan_mode}")
        
        # Execute exploit discovery analysis
        main_logger.info("Executing command: advanced_exploit_discovery")
        
        # Execute project scanning with exploit discovery focus
        lancedb, lance_table_name, project_audit = scan_project(project, engine)

        # Agentic orchestrator pipeline: mine invariants -> plan & validate on fork
        try:
            miner = InvariantMiner()
            invariants = miner.mine(project_audit)
            orchestrator = Orchestrator(project.id)
            findings = orchestrator.run_defensive_assessment(
                contract_targets=list({f.get('contract_name', '') for f in project_audit.functions_to_check}),
                context={"invariants": invariants}
            )
            # Optionally persist orchestrator findings to logs
            log_data_info(main_logger, "Orchestrator findings", len(findings))
        except Exception as e:
            log_warning(main_logger, f"Orchestrator pipeline skipped: {e}")
        
        # Execute vulnerability validation based on scanning mode
        if scan_mode in ["COMMON_PROJECT", "PURE_SCAN", "CHECKLIST", "COMMON_PROJECT_FINE_GRAINED"]:
            main_logger.info(f"Scanning mode '{scan_mode}' requires vulnerability validation")
            check_function_vul(engine, lancedb, lance_table_name, project_audit)
        else:
            main_logger.info(f"Scanning mode '{scan_mode}' skips vulnerability validation step")

        # Calculate total execution time
        end_time = time.time()
        total_duration = end_time - start_time
        log_success(main_logger, "All exploit discovery tasks completed", f"Total duration: {total_duration:.2f}s")
        
        # Generate comprehensive exploit analysis report
        log_step(main_logger, "Generating comprehensive exploit analysis report")
        excel_start = time.time()
        ResProcessor.generate_excel(args.output, project.id, engine)
        excel_duration = time.time() - excel_start
        log_success(main_logger, "Exploit analysis report generated", f"Duration: {excel_duration:.2f}s, File: {args.output}")
        
        log_section_end(main_logger, "Advanced Exploit Discovery Mode", time.time() - main_start_time)