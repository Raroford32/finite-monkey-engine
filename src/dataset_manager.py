#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced dataset manager for exploit discovery
Migrated from library/dataset_utils.py, specialized for handling project datasets
"""

import os
import json

def load_dataset(dataset_path, external_project_id=None, external_project_path=None):
    """
    Load dataset configuration for exploit discovery
    
    Args:
        dataset_path: Dataset base path
        external_project_id: External project ID
        external_project_path: External project path
    
    Returns:
        dict: Project configuration dictionary
    """
    # Load projects from datasets.json
    if not external_project_id and not external_project_path:
        ds_json = os.path.join(dataset_path, "datasets.json")
        dj = json.load(open(ds_json, 'r', encoding='utf-8'))
        projects = {}
        for k, v in dj.items():
            v['base_path'] = dataset_path
            projects[k] = v

    # Handle external project input
    if external_project_id and external_project_path:
        projects = {}
        # Construct project data structure for the external project
        external_project = {
            'path': external_project_path,
            'base_path': dataset_path
        }

        # Add the external project to the projects dictionary
        projects[external_project_id] = external_project

    return projects


class Project(object):
    """Enhanced project configuration class for exploit discovery"""
    
    def __init__(self, id, project) -> None:
        self.id = id
        # Handle both absolute and relative paths
        if project.get('base_path', ''):
            self.path = os.path.join(project['base_path'], project['path'])
        else:
            # For absolute paths or when base_path is empty
            self.path = project['path'] 