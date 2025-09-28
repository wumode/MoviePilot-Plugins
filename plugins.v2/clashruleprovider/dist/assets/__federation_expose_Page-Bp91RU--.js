import { importShared } from './__federation_fn_import-JrT3xvdd.js';
import { c as commonjsGlobal, g as getDefaultExportFromCjs, V as VAceEditor } from './theme-monokai-Bn79mBHh.js';
import { _ as _export_sfc } from './_plugin-vue_export-helper-pcqpp-6-.js';

/*! js-yaml 4.1.0 https://github.com/nodeca/js-yaml @license MIT */
function isNothing(subject) {
  return (typeof subject === 'undefined') || (subject === null);
}


function isObject$1(subject) {
  return (typeof subject === 'object') && (subject !== null);
}


function toArray(sequence) {
  if (Array.isArray(sequence)) return sequence;
  else if (isNothing(sequence)) return [];

  return [ sequence ];
}


function extend(target, source) {
  var index, length, key, sourceKeys;

  if (source) {
    sourceKeys = Object.keys(source);

    for (index = 0, length = sourceKeys.length; index < length; index += 1) {
      key = sourceKeys[index];
      target[key] = source[key];
    }
  }

  return target;
}


function repeat(string, count) {
  var result = '', cycle;

  for (cycle = 0; cycle < count; cycle += 1) {
    result += string;
  }

  return result;
}


function isNegativeZero(number) {
  return (number === 0) && (Number.NEGATIVE_INFINITY === 1 / number);
}


var isNothing_1      = isNothing;
var isObject_1       = isObject$1;
var toArray_1        = toArray;
var repeat_1         = repeat;
var isNegativeZero_1 = isNegativeZero;
var extend_1         = extend;

var common = {
	isNothing: isNothing_1,
	isObject: isObject_1,
	toArray: toArray_1,
	repeat: repeat_1,
	isNegativeZero: isNegativeZero_1,
	extend: extend_1
};

// YAML error class. http://stackoverflow.com/questions/8458984


function formatError(exception, compact) {
  var where = '', message = exception.reason || '(unknown reason)';

  if (!exception.mark) return message;

  if (exception.mark.name) {
    where += 'in "' + exception.mark.name + '" ';
  }

  where += '(' + (exception.mark.line + 1) + ':' + (exception.mark.column + 1) + ')';

  if (!compact && exception.mark.snippet) {
    where += '\n\n' + exception.mark.snippet;
  }

  return message + ' ' + where;
}


function YAMLException$1(reason, mark) {
  // Super constructor
  Error.call(this);

  this.name = 'YAMLException';
  this.reason = reason;
  this.mark = mark;
  this.message = formatError(this, false);

  // Include stack trace in error object
  if (Error.captureStackTrace) {
    // Chrome and NodeJS
    Error.captureStackTrace(this, this.constructor);
  } else {
    // FF, IE 10+ and Safari 6+. Fallback for others
    this.stack = (new Error()).stack || '';
  }
}


// Inherit from Error
YAMLException$1.prototype = Object.create(Error.prototype);
YAMLException$1.prototype.constructor = YAMLException$1;


YAMLException$1.prototype.toString = function toString(compact) {
  return this.name + ': ' + formatError(this, compact);
};


var exception = YAMLException$1;

// get snippet for a single line, respecting maxLength
function getLine(buffer, lineStart, lineEnd, position, maxLineLength) {
  var head = '';
  var tail = '';
  var maxHalfLength = Math.floor(maxLineLength / 2) - 1;

  if (position - lineStart > maxHalfLength) {
    head = ' ... ';
    lineStart = position - maxHalfLength + head.length;
  }

  if (lineEnd - position > maxHalfLength) {
    tail = ' ...';
    lineEnd = position + maxHalfLength - tail.length;
  }

  return {
    str: head + buffer.slice(lineStart, lineEnd).replace(/\t/g, '→') + tail,
    pos: position - lineStart + head.length // relative position
  };
}


function padStart(string, max) {
  return common.repeat(' ', max - string.length) + string;
}


function makeSnippet(mark, options) {
  options = Object.create(options || null);

  if (!mark.buffer) return null;

  if (!options.maxLength) options.maxLength = 79;
  if (typeof options.indent      !== 'number') options.indent      = 1;
  if (typeof options.linesBefore !== 'number') options.linesBefore = 3;
  if (typeof options.linesAfter  !== 'number') options.linesAfter  = 2;

  var re = /\r?\n|\r|\0/g;
  var lineStarts = [ 0 ];
  var lineEnds = [];
  var match;
  var foundLineNo = -1;

  while ((match = re.exec(mark.buffer))) {
    lineEnds.push(match.index);
    lineStarts.push(match.index + match[0].length);

    if (mark.position <= match.index && foundLineNo < 0) {
      foundLineNo = lineStarts.length - 2;
    }
  }

  if (foundLineNo < 0) foundLineNo = lineStarts.length - 1;

  var result = '', i, line;
  var lineNoLength = Math.min(mark.line + options.linesAfter, lineEnds.length).toString().length;
  var maxLineLength = options.maxLength - (options.indent + lineNoLength + 3);

  for (i = 1; i <= options.linesBefore; i++) {
    if (foundLineNo - i < 0) break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo - i],
      lineEnds[foundLineNo - i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo - i]),
      maxLineLength
    );
    result = common.repeat(' ', options.indent) + padStart((mark.line - i + 1).toString(), lineNoLength) +
      ' | ' + line.str + '\n' + result;
  }

  line = getLine(mark.buffer, lineStarts[foundLineNo], lineEnds[foundLineNo], mark.position, maxLineLength);
  result += common.repeat(' ', options.indent) + padStart((mark.line + 1).toString(), lineNoLength) +
    ' | ' + line.str + '\n';
  result += common.repeat('-', options.indent + lineNoLength + 3 + line.pos) + '^' + '\n';

  for (i = 1; i <= options.linesAfter; i++) {
    if (foundLineNo + i >= lineEnds.length) break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo + i],
      lineEnds[foundLineNo + i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo + i]),
      maxLineLength
    );
    result += common.repeat(' ', options.indent) + padStart((mark.line + i + 1).toString(), lineNoLength) +
      ' | ' + line.str + '\n';
  }

  return result.replace(/\n$/, '');
}


var snippet = makeSnippet;

var TYPE_CONSTRUCTOR_OPTIONS = [
  'kind',
  'multi',
  'resolve',
  'construct',
  'instanceOf',
  'predicate',
  'represent',
  'representName',
  'defaultStyle',
  'styleAliases'
];

var YAML_NODE_KINDS = [
  'scalar',
  'sequence',
  'mapping'
];

function compileStyleAliases(map) {
  var result = {};

  if (map !== null) {
    Object.keys(map).forEach(function (style) {
      map[style].forEach(function (alias) {
        result[String(alias)] = style;
      });
    });
  }

  return result;
}

function Type$1(tag, options) {
  options = options || {};

  Object.keys(options).forEach(function (name) {
    if (TYPE_CONSTRUCTOR_OPTIONS.indexOf(name) === -1) {
      throw new exception('Unknown option "' + name + '" is met in definition of "' + tag + '" YAML type.');
    }
  });

  // TODO: Add tag format check.
  this.options       = options; // keep original options in case user wants to extend this type later
  this.tag           = tag;
  this.kind          = options['kind']          || null;
  this.resolve       = options['resolve']       || function () { return true; };
  this.construct     = options['construct']     || function (data) { return data; };
  this.instanceOf    = options['instanceOf']    || null;
  this.predicate     = options['predicate']     || null;
  this.represent     = options['represent']     || null;
  this.representName = options['representName'] || null;
  this.defaultStyle  = options['defaultStyle']  || null;
  this.multi         = options['multi']         || false;
  this.styleAliases  = compileStyleAliases(options['styleAliases'] || null);

  if (YAML_NODE_KINDS.indexOf(this.kind) === -1) {
    throw new exception('Unknown kind "' + this.kind + '" is specified for "' + tag + '" YAML type.');
  }
}

var type = Type$1;

/*eslint-disable max-len*/





function compileList(schema, name) {
  var result = [];

  schema[name].forEach(function (currentType) {
    var newIndex = result.length;

    result.forEach(function (previousType, previousIndex) {
      if (previousType.tag === currentType.tag &&
          previousType.kind === currentType.kind &&
          previousType.multi === currentType.multi) {

        newIndex = previousIndex;
      }
    });

    result[newIndex] = currentType;
  });

  return result;
}


function compileMap(/* lists... */) {
  var result = {
        scalar: {},
        sequence: {},
        mapping: {},
        fallback: {},
        multi: {
          scalar: [],
          sequence: [],
          mapping: [],
          fallback: []
        }
      }, index, length;

  function collectType(type) {
    if (type.multi) {
      result.multi[type.kind].push(type);
      result.multi['fallback'].push(type);
    } else {
      result[type.kind][type.tag] = result['fallback'][type.tag] = type;
    }
  }

  for (index = 0, length = arguments.length; index < length; index += 1) {
    arguments[index].forEach(collectType);
  }
  return result;
}


function Schema$1(definition) {
  return this.extend(definition);
}


Schema$1.prototype.extend = function extend(definition) {
  var implicit = [];
  var explicit = [];

  if (definition instanceof type) {
    // Schema.extend(type)
    explicit.push(definition);

  } else if (Array.isArray(definition)) {
    // Schema.extend([ type1, type2, ... ])
    explicit = explicit.concat(definition);

  } else if (definition && (Array.isArray(definition.implicit) || Array.isArray(definition.explicit))) {
    // Schema.extend({ explicit: [ type1, type2, ... ], implicit: [ type1, type2, ... ] })
    if (definition.implicit) implicit = implicit.concat(definition.implicit);
    if (definition.explicit) explicit = explicit.concat(definition.explicit);

  } else {
    throw new exception('Schema.extend argument should be a Type, [ Type ], ' +
      'or a schema definition ({ implicit: [...], explicit: [...] })');
  }

  implicit.forEach(function (type$1) {
    if (!(type$1 instanceof type)) {
      throw new exception('Specified list of YAML types (or a single Type object) contains a non-Type object.');
    }

    if (type$1.loadKind && type$1.loadKind !== 'scalar') {
      throw new exception('There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.');
    }

    if (type$1.multi) {
      throw new exception('There is a multi type in the implicit list of a schema. Multi tags can only be listed as explicit.');
    }
  });

  explicit.forEach(function (type$1) {
    if (!(type$1 instanceof type)) {
      throw new exception('Specified list of YAML types (or a single Type object) contains a non-Type object.');
    }
  });

  var result = Object.create(Schema$1.prototype);

  result.implicit = (this.implicit || []).concat(implicit);
  result.explicit = (this.explicit || []).concat(explicit);

  result.compiledImplicit = compileList(result, 'implicit');
  result.compiledExplicit = compileList(result, 'explicit');
  result.compiledTypeMap  = compileMap(result.compiledImplicit, result.compiledExplicit);

  return result;
};


var schema = Schema$1;

var str = new type('tag:yaml.org,2002:str', {
  kind: 'scalar',
  construct: function (data) { return data !== null ? data : ''; }
});

var seq = new type('tag:yaml.org,2002:seq', {
  kind: 'sequence',
  construct: function (data) { return data !== null ? data : []; }
});

var map = new type('tag:yaml.org,2002:map', {
  kind: 'mapping',
  construct: function (data) { return data !== null ? data : {}; }
});

var failsafe = new schema({
  explicit: [
    str,
    seq,
    map
  ]
});

function resolveYamlNull(data) {
  if (data === null) return true;

  var max = data.length;

  return (max === 1 && data === '~') ||
         (max === 4 && (data === 'null' || data === 'Null' || data === 'NULL'));
}

function constructYamlNull() {
  return null;
}

function isNull(object) {
  return object === null;
}

var _null = new type('tag:yaml.org,2002:null', {
  kind: 'scalar',
  resolve: resolveYamlNull,
  construct: constructYamlNull,
  predicate: isNull,
  represent: {
    canonical: function () { return '~';    },
    lowercase: function () { return 'null'; },
    uppercase: function () { return 'NULL'; },
    camelcase: function () { return 'Null'; },
    empty:     function () { return '';     }
  },
  defaultStyle: 'lowercase'
});

function resolveYamlBoolean(data) {
  if (data === null) return false;

  var max = data.length;

  return (max === 4 && (data === 'true' || data === 'True' || data === 'TRUE')) ||
         (max === 5 && (data === 'false' || data === 'False' || data === 'FALSE'));
}

function constructYamlBoolean(data) {
  return data === 'true' ||
         data === 'True' ||
         data === 'TRUE';
}

function isBoolean(object) {
  return Object.prototype.toString.call(object) === '[object Boolean]';
}

var bool = new type('tag:yaml.org,2002:bool', {
  kind: 'scalar',
  resolve: resolveYamlBoolean,
  construct: constructYamlBoolean,
  predicate: isBoolean,
  represent: {
    lowercase: function (object) { return object ? 'true' : 'false'; },
    uppercase: function (object) { return object ? 'TRUE' : 'FALSE'; },
    camelcase: function (object) { return object ? 'True' : 'False'; }
  },
  defaultStyle: 'lowercase'
});

function isHexCode(c) {
  return ((0x30/* 0 */ <= c) && (c <= 0x39/* 9 */)) ||
         ((0x41/* A */ <= c) && (c <= 0x46/* F */)) ||
         ((0x61/* a */ <= c) && (c <= 0x66/* f */));
}

function isOctCode(c) {
  return ((0x30/* 0 */ <= c) && (c <= 0x37/* 7 */));
}

function isDecCode(c) {
  return ((0x30/* 0 */ <= c) && (c <= 0x39/* 9 */));
}

function resolveYamlInteger(data) {
  if (data === null) return false;

  var max = data.length,
      index = 0,
      hasDigits = false,
      ch;

  if (!max) return false;

  ch = data[index];

  // sign
  if (ch === '-' || ch === '+') {
    ch = data[++index];
  }

  if (ch === '0') {
    // 0
    if (index + 1 === max) return true;
    ch = data[++index];

    // base 2, base 8, base 16

    if (ch === 'b') {
      // base 2
      index++;

      for (; index < max; index++) {
        ch = data[index];
        if (ch === '_') continue;
        if (ch !== '0' && ch !== '1') return false;
        hasDigits = true;
      }
      return hasDigits && ch !== '_';
    }


    if (ch === 'x') {
      // base 16
      index++;

      for (; index < max; index++) {
        ch = data[index];
        if (ch === '_') continue;
        if (!isHexCode(data.charCodeAt(index))) return false;
        hasDigits = true;
      }
      return hasDigits && ch !== '_';
    }


    if (ch === 'o') {
      // base 8
      index++;

      for (; index < max; index++) {
        ch = data[index];
        if (ch === '_') continue;
        if (!isOctCode(data.charCodeAt(index))) return false;
        hasDigits = true;
      }
      return hasDigits && ch !== '_';
    }
  }

  // base 10 (except 0)

  // value should not start with `_`;
  if (ch === '_') return false;

  for (; index < max; index++) {
    ch = data[index];
    if (ch === '_') continue;
    if (!isDecCode(data.charCodeAt(index))) {
      return false;
    }
    hasDigits = true;
  }

  // Should have digits and should not end with `_`
  if (!hasDigits || ch === '_') return false;

  return true;
}

function constructYamlInteger(data) {
  var value = data, sign = 1, ch;

  if (value.indexOf('_') !== -1) {
    value = value.replace(/_/g, '');
  }

  ch = value[0];

  if (ch === '-' || ch === '+') {
    if (ch === '-') sign = -1;
    value = value.slice(1);
    ch = value[0];
  }

  if (value === '0') return 0;

  if (ch === '0') {
    if (value[1] === 'b') return sign * parseInt(value.slice(2), 2);
    if (value[1] === 'x') return sign * parseInt(value.slice(2), 16);
    if (value[1] === 'o') return sign * parseInt(value.slice(2), 8);
  }

  return sign * parseInt(value, 10);
}

function isInteger(object) {
  return (Object.prototype.toString.call(object)) === '[object Number]' &&
         (object % 1 === 0 && !common.isNegativeZero(object));
}

var int = new type('tag:yaml.org,2002:int', {
  kind: 'scalar',
  resolve: resolveYamlInteger,
  construct: constructYamlInteger,
  predicate: isInteger,
  represent: {
    binary:      function (obj) { return obj >= 0 ? '0b' + obj.toString(2) : '-0b' + obj.toString(2).slice(1); },
    octal:       function (obj) { return obj >= 0 ? '0o'  + obj.toString(8) : '-0o'  + obj.toString(8).slice(1); },
    decimal:     function (obj) { return obj.toString(10); },
    /* eslint-disable max-len */
    hexadecimal: function (obj) { return obj >= 0 ? '0x' + obj.toString(16).toUpperCase() :  '-0x' + obj.toString(16).toUpperCase().slice(1); }
  },
  defaultStyle: 'decimal',
  styleAliases: {
    binary:      [ 2,  'bin' ],
    octal:       [ 8,  'oct' ],
    decimal:     [ 10, 'dec' ],
    hexadecimal: [ 16, 'hex' ]
  }
});

var YAML_FLOAT_PATTERN = new RegExp(
  // 2.5e4, 2.5 and integers
  '^(?:[-+]?(?:[0-9][0-9_]*)(?:\\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?' +
  // .2e4, .2
  // special case, seems not from spec
  '|\\.[0-9_]+(?:[eE][-+]?[0-9]+)?' +
  // .inf
  '|[-+]?\\.(?:inf|Inf|INF)' +
  // .nan
  '|\\.(?:nan|NaN|NAN))$');

function resolveYamlFloat(data) {
  if (data === null) return false;

  if (!YAML_FLOAT_PATTERN.test(data) ||
      // Quick hack to not allow integers end with `_`
      // Probably should update regexp & check speed
      data[data.length - 1] === '_') {
    return false;
  }

  return true;
}

function constructYamlFloat(data) {
  var value, sign;

  value  = data.replace(/_/g, '').toLowerCase();
  sign   = value[0] === '-' ? -1 : 1;

  if ('+-'.indexOf(value[0]) >= 0) {
    value = value.slice(1);
  }

  if (value === '.inf') {
    return (sign === 1) ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;

  } else if (value === '.nan') {
    return NaN;
  }
  return sign * parseFloat(value, 10);
}


var SCIENTIFIC_WITHOUT_DOT = /^[-+]?[0-9]+e/;

function representYamlFloat(object, style) {
  var res;

  if (isNaN(object)) {
    switch (style) {
      case 'lowercase': return '.nan';
      case 'uppercase': return '.NAN';
      case 'camelcase': return '.NaN';
    }
  } else if (Number.POSITIVE_INFINITY === object) {
    switch (style) {
      case 'lowercase': return '.inf';
      case 'uppercase': return '.INF';
      case 'camelcase': return '.Inf';
    }
  } else if (Number.NEGATIVE_INFINITY === object) {
    switch (style) {
      case 'lowercase': return '-.inf';
      case 'uppercase': return '-.INF';
      case 'camelcase': return '-.Inf';
    }
  } else if (common.isNegativeZero(object)) {
    return '-0.0';
  }

  res = object.toString(10);

  // JS stringifier can build scientific format without dots: 5e-100,
  // while YAML requres dot: 5.e-100. Fix it with simple hack

  return SCIENTIFIC_WITHOUT_DOT.test(res) ? res.replace('e', '.e') : res;
}

function isFloat(object) {
  return (Object.prototype.toString.call(object) === '[object Number]') &&
         (object % 1 !== 0 || common.isNegativeZero(object));
}

var float = new type('tag:yaml.org,2002:float', {
  kind: 'scalar',
  resolve: resolveYamlFloat,
  construct: constructYamlFloat,
  predicate: isFloat,
  represent: representYamlFloat,
  defaultStyle: 'lowercase'
});

var json = failsafe.extend({
  implicit: [
    _null,
    bool,
    int,
    float
  ]
});

var core = json;

var YAML_DATE_REGEXP = new RegExp(
  '^([0-9][0-9][0-9][0-9])'          + // [1] year
  '-([0-9][0-9])'                    + // [2] month
  '-([0-9][0-9])$');                   // [3] day

var YAML_TIMESTAMP_REGEXP = new RegExp(
  '^([0-9][0-9][0-9][0-9])'          + // [1] year
  '-([0-9][0-9]?)'                   + // [2] month
  '-([0-9][0-9]?)'                   + // [3] day
  '(?:[Tt]|[ \\t]+)'                 + // ...
  '([0-9][0-9]?)'                    + // [4] hour
  ':([0-9][0-9])'                    + // [5] minute
  ':([0-9][0-9])'                    + // [6] second
  '(?:\\.([0-9]*))?'                 + // [7] fraction
  '(?:[ \\t]*(Z|([-+])([0-9][0-9]?)' + // [8] tz [9] tz_sign [10] tz_hour
  '(?::([0-9][0-9]))?))?$');           // [11] tz_minute

function resolveYamlTimestamp(data) {
  if (data === null) return false;
  if (YAML_DATE_REGEXP.exec(data) !== null) return true;
  if (YAML_TIMESTAMP_REGEXP.exec(data) !== null) return true;
  return false;
}

function constructYamlTimestamp(data) {
  var match, year, month, day, hour, minute, second, fraction = 0,
      delta = null, tz_hour, tz_minute, date;

  match = YAML_DATE_REGEXP.exec(data);
  if (match === null) match = YAML_TIMESTAMP_REGEXP.exec(data);

  if (match === null) throw new Error('Date resolve error');

  // match: [1] year [2] month [3] day

  year = +(match[1]);
  month = +(match[2]) - 1; // JS month starts with 0
  day = +(match[3]);

  if (!match[4]) { // no hour
    return new Date(Date.UTC(year, month, day));
  }

  // match: [4] hour [5] minute [6] second [7] fraction

  hour = +(match[4]);
  minute = +(match[5]);
  second = +(match[6]);

  if (match[7]) {
    fraction = match[7].slice(0, 3);
    while (fraction.length < 3) { // milli-seconds
      fraction += '0';
    }
    fraction = +fraction;
  }

  // match: [8] tz [9] tz_sign [10] tz_hour [11] tz_minute

  if (match[9]) {
    tz_hour = +(match[10]);
    tz_minute = +(match[11] || 0);
    delta = (tz_hour * 60 + tz_minute) * 60000; // delta in mili-seconds
    if (match[9] === '-') delta = -delta;
  }

  date = new Date(Date.UTC(year, month, day, hour, minute, second, fraction));

  if (delta) date.setTime(date.getTime() - delta);

  return date;
}

function representYamlTimestamp(object /*, style*/) {
  return object.toISOString();
}

var timestamp = new type('tag:yaml.org,2002:timestamp', {
  kind: 'scalar',
  resolve: resolveYamlTimestamp,
  construct: constructYamlTimestamp,
  instanceOf: Date,
  represent: representYamlTimestamp
});

function resolveYamlMerge(data) {
  return data === '<<' || data === null;
}

var merge = new type('tag:yaml.org,2002:merge', {
  kind: 'scalar',
  resolve: resolveYamlMerge
});

/*eslint-disable no-bitwise*/





// [ 64, 65, 66 ] -> [ padding, CR, LF ]
var BASE64_MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r';


function resolveYamlBinary(data) {
  if (data === null) return false;

  var code, idx, bitlen = 0, max = data.length, map = BASE64_MAP;

  // Convert one by one.
  for (idx = 0; idx < max; idx++) {
    code = map.indexOf(data.charAt(idx));

    // Skip CR/LF
    if (code > 64) continue;

    // Fail on illegal characters
    if (code < 0) return false;

    bitlen += 6;
  }

  // If there are any bits left, source was corrupted
  return (bitlen % 8) === 0;
}

function constructYamlBinary(data) {
  var idx, tailbits,
      input = data.replace(/[\r\n=]/g, ''), // remove CR/LF & padding to simplify scan
      max = input.length,
      map = BASE64_MAP,
      bits = 0,
      result = [];

  // Collect by 6*4 bits (3 bytes)

  for (idx = 0; idx < max; idx++) {
    if ((idx % 4 === 0) && idx) {
      result.push((bits >> 16) & 0xFF);
      result.push((bits >> 8) & 0xFF);
      result.push(bits & 0xFF);
    }

    bits = (bits << 6) | map.indexOf(input.charAt(idx));
  }

  // Dump tail

  tailbits = (max % 4) * 6;

  if (tailbits === 0) {
    result.push((bits >> 16) & 0xFF);
    result.push((bits >> 8) & 0xFF);
    result.push(bits & 0xFF);
  } else if (tailbits === 18) {
    result.push((bits >> 10) & 0xFF);
    result.push((bits >> 2) & 0xFF);
  } else if (tailbits === 12) {
    result.push((bits >> 4) & 0xFF);
  }

  return new Uint8Array(result);
}

function representYamlBinary(object /*, style*/) {
  var result = '', bits = 0, idx, tail,
      max = object.length,
      map = BASE64_MAP;

  // Convert every three bytes to 4 ASCII characters.

  for (idx = 0; idx < max; idx++) {
    if ((idx % 3 === 0) && idx) {
      result += map[(bits >> 18) & 0x3F];
      result += map[(bits >> 12) & 0x3F];
      result += map[(bits >> 6) & 0x3F];
      result += map[bits & 0x3F];
    }

    bits = (bits << 8) + object[idx];
  }

  // Dump tail

  tail = max % 3;

  if (tail === 0) {
    result += map[(bits >> 18) & 0x3F];
    result += map[(bits >> 12) & 0x3F];
    result += map[(bits >> 6) & 0x3F];
    result += map[bits & 0x3F];
  } else if (tail === 2) {
    result += map[(bits >> 10) & 0x3F];
    result += map[(bits >> 4) & 0x3F];
    result += map[(bits << 2) & 0x3F];
    result += map[64];
  } else if (tail === 1) {
    result += map[(bits >> 2) & 0x3F];
    result += map[(bits << 4) & 0x3F];
    result += map[64];
    result += map[64];
  }

  return result;
}

function isBinary(obj) {
  return Object.prototype.toString.call(obj) ===  '[object Uint8Array]';
}

var binary = new type('tag:yaml.org,2002:binary', {
  kind: 'scalar',
  resolve: resolveYamlBinary,
  construct: constructYamlBinary,
  predicate: isBinary,
  represent: representYamlBinary
});

var _hasOwnProperty$3 = Object.prototype.hasOwnProperty;
var _toString$2       = Object.prototype.toString;

function resolveYamlOmap(data) {
  if (data === null) return true;

  var objectKeys = [], index, length, pair, pairKey, pairHasKey,
      object = data;

  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    pairHasKey = false;

    if (_toString$2.call(pair) !== '[object Object]') return false;

    for (pairKey in pair) {
      if (_hasOwnProperty$3.call(pair, pairKey)) {
        if (!pairHasKey) pairHasKey = true;
        else return false;
      }
    }

    if (!pairHasKey) return false;

    if (objectKeys.indexOf(pairKey) === -1) objectKeys.push(pairKey);
    else return false;
  }

  return true;
}

function constructYamlOmap(data) {
  return data !== null ? data : [];
}

var omap = new type('tag:yaml.org,2002:omap', {
  kind: 'sequence',
  resolve: resolveYamlOmap,
  construct: constructYamlOmap
});

var _toString$1 = Object.prototype.toString;

function resolveYamlPairs(data) {
  if (data === null) return true;

  var index, length, pair, keys, result,
      object = data;

  result = new Array(object.length);

  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];

    if (_toString$1.call(pair) !== '[object Object]') return false;

    keys = Object.keys(pair);

    if (keys.length !== 1) return false;

    result[index] = [ keys[0], pair[keys[0]] ];
  }

  return true;
}

function constructYamlPairs(data) {
  if (data === null) return [];

  var index, length, pair, keys, result,
      object = data;

  result = new Array(object.length);

  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];

    keys = Object.keys(pair);

    result[index] = [ keys[0], pair[keys[0]] ];
  }

  return result;
}

var pairs = new type('tag:yaml.org,2002:pairs', {
  kind: 'sequence',
  resolve: resolveYamlPairs,
  construct: constructYamlPairs
});

var _hasOwnProperty$2 = Object.prototype.hasOwnProperty;

function resolveYamlSet(data) {
  if (data === null) return true;

  var key, object = data;

  for (key in object) {
    if (_hasOwnProperty$2.call(object, key)) {
      if (object[key] !== null) return false;
    }
  }

  return true;
}

function constructYamlSet(data) {
  return data !== null ? data : {};
}

var set = new type('tag:yaml.org,2002:set', {
  kind: 'mapping',
  resolve: resolveYamlSet,
  construct: constructYamlSet
});

var _default = core.extend({
  implicit: [
    timestamp,
    merge
  ],
  explicit: [
    binary,
    omap,
    pairs,
    set
  ]
});

/*eslint-disable max-len,no-use-before-define*/







var _hasOwnProperty$1 = Object.prototype.hasOwnProperty;


var CONTEXT_FLOW_IN   = 1;
var CONTEXT_FLOW_OUT  = 2;
var CONTEXT_BLOCK_IN  = 3;
var CONTEXT_BLOCK_OUT = 4;


var CHOMPING_CLIP  = 1;
var CHOMPING_STRIP = 2;
var CHOMPING_KEEP  = 3;


var PATTERN_NON_PRINTABLE         = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
var PATTERN_NON_ASCII_LINE_BREAKS = /[\x85\u2028\u2029]/;
var PATTERN_FLOW_INDICATORS       = /[,\[\]\{\}]/;
var PATTERN_TAG_HANDLE            = /^(?:!|!!|![a-z\-]+!)$/i;
var PATTERN_TAG_URI               = /^(?:!|[^,\[\]\{\}])(?:%[0-9a-f]{2}|[0-9a-z\-#;\/\?:@&=\+\$,_\.!~\*'\(\)\[\]])*$/i;


function _class(obj) { return Object.prototype.toString.call(obj); }

function is_EOL(c) {
  return (c === 0x0A/* LF */) || (c === 0x0D/* CR */);
}

function is_WHITE_SPACE(c) {
  return (c === 0x09/* Tab */) || (c === 0x20/* Space */);
}

function is_WS_OR_EOL(c) {
  return (c === 0x09/* Tab */) ||
         (c === 0x20/* Space */) ||
         (c === 0x0A/* LF */) ||
         (c === 0x0D/* CR */);
}

function is_FLOW_INDICATOR(c) {
  return c === 0x2C/* , */ ||
         c === 0x5B/* [ */ ||
         c === 0x5D/* ] */ ||
         c === 0x7B/* { */ ||
         c === 0x7D/* } */;
}

function fromHexCode(c) {
  var lc;

  if ((0x30/* 0 */ <= c) && (c <= 0x39/* 9 */)) {
    return c - 0x30;
  }

  /*eslint-disable no-bitwise*/
  lc = c | 0x20;

  if ((0x61/* a */ <= lc) && (lc <= 0x66/* f */)) {
    return lc - 0x61 + 10;
  }

  return -1;
}

function escapedHexLen(c) {
  if (c === 0x78/* x */) { return 2; }
  if (c === 0x75/* u */) { return 4; }
  if (c === 0x55/* U */) { return 8; }
  return 0;
}

function fromDecimalCode(c) {
  if ((0x30/* 0 */ <= c) && (c <= 0x39/* 9 */)) {
    return c - 0x30;
  }

  return -1;
}

function simpleEscapeSequence(c) {
  /* eslint-disable indent */
  return (c === 0x30/* 0 */) ? '\x00' :
        (c === 0x61/* a */) ? '\x07' :
        (c === 0x62/* b */) ? '\x08' :
        (c === 0x74/* t */) ? '\x09' :
        (c === 0x09/* Tab */) ? '\x09' :
        (c === 0x6E/* n */) ? '\x0A' :
        (c === 0x76/* v */) ? '\x0B' :
        (c === 0x66/* f */) ? '\x0C' :
        (c === 0x72/* r */) ? '\x0D' :
        (c === 0x65/* e */) ? '\x1B' :
        (c === 0x20/* Space */) ? ' ' :
        (c === 0x22/* " */) ? '\x22' :
        (c === 0x2F/* / */) ? '/' :
        (c === 0x5C/* \ */) ? '\x5C' :
        (c === 0x4E/* N */) ? '\x85' :
        (c === 0x5F/* _ */) ? '\xA0' :
        (c === 0x4C/* L */) ? '\u2028' :
        (c === 0x50/* P */) ? '\u2029' : '';
}

function charFromCodepoint(c) {
  if (c <= 0xFFFF) {
    return String.fromCharCode(c);
  }
  // Encode UTF-16 surrogate pair
  // https://en.wikipedia.org/wiki/UTF-16#Code_points_U.2B010000_to_U.2B10FFFF
  return String.fromCharCode(
    ((c - 0x010000) >> 10) + 0xD800,
    ((c - 0x010000) & 0x03FF) + 0xDC00
  );
}

var simpleEscapeCheck = new Array(256); // integer, for fast access
var simpleEscapeMap = new Array(256);
for (var i = 0; i < 256; i++) {
  simpleEscapeCheck[i] = simpleEscapeSequence(i) ? 1 : 0;
  simpleEscapeMap[i] = simpleEscapeSequence(i);
}


function State$1(input, options) {
  this.input = input;

  this.filename  = options['filename']  || null;
  this.schema    = options['schema']    || _default;
  this.onWarning = options['onWarning'] || null;
  // (Hidden) Remove? makes the loader to expect YAML 1.1 documents
  // if such documents have no explicit %YAML directive
  this.legacy    = options['legacy']    || false;

  this.json      = options['json']      || false;
  this.listener  = options['listener']  || null;

  this.implicitTypes = this.schema.compiledImplicit;
  this.typeMap       = this.schema.compiledTypeMap;

  this.length     = input.length;
  this.position   = 0;
  this.line       = 0;
  this.lineStart  = 0;
  this.lineIndent = 0;

  // position of first leading tab in the current line,
  // used to make sure there are no tabs in the indentation
  this.firstTabInLine = -1;

  this.documents = [];

  /*
  this.version;
  this.checkLineBreaks;
  this.tagMap;
  this.anchorMap;
  this.tag;
  this.anchor;
  this.kind;
  this.result;*/

}


function generateError(state, message) {
  var mark = {
    name:     state.filename,
    buffer:   state.input.slice(0, -1), // omit trailing \0
    position: state.position,
    line:     state.line,
    column:   state.position - state.lineStart
  };

  mark.snippet = snippet(mark);

  return new exception(message, mark);
}

function throwError(state, message) {
  throw generateError(state, message);
}

function throwWarning(state, message) {
  if (state.onWarning) {
    state.onWarning.call(null, generateError(state, message));
  }
}


var directiveHandlers = {

  YAML: function handleYamlDirective(state, name, args) {

    var match, major, minor;

    if (state.version !== null) {
      throwError(state, 'duplication of %YAML directive');
    }

    if (args.length !== 1) {
      throwError(state, 'YAML directive accepts exactly one argument');
    }

    match = /^([0-9]+)\.([0-9]+)$/.exec(args[0]);

    if (match === null) {
      throwError(state, 'ill-formed argument of the YAML directive');
    }

    major = parseInt(match[1], 10);
    minor = parseInt(match[2], 10);

    if (major !== 1) {
      throwError(state, 'unacceptable YAML version of the document');
    }

    state.version = args[0];
    state.checkLineBreaks = (minor < 2);

    if (minor !== 1 && minor !== 2) {
      throwWarning(state, 'unsupported YAML version of the document');
    }
  },

  TAG: function handleTagDirective(state, name, args) {

    var handle, prefix;

    if (args.length !== 2) {
      throwError(state, 'TAG directive accepts exactly two arguments');
    }

    handle = args[0];
    prefix = args[1];

    if (!PATTERN_TAG_HANDLE.test(handle)) {
      throwError(state, 'ill-formed tag handle (first argument) of the TAG directive');
    }

    if (_hasOwnProperty$1.call(state.tagMap, handle)) {
      throwError(state, 'there is a previously declared suffix for "' + handle + '" tag handle');
    }

    if (!PATTERN_TAG_URI.test(prefix)) {
      throwError(state, 'ill-formed tag prefix (second argument) of the TAG directive');
    }

    try {
      prefix = decodeURIComponent(prefix);
    } catch (err) {
      throwError(state, 'tag prefix is malformed: ' + prefix);
    }

    state.tagMap[handle] = prefix;
  }
};


function captureSegment(state, start, end, checkJson) {
  var _position, _length, _character, _result;

  if (start < end) {
    _result = state.input.slice(start, end);

    if (checkJson) {
      for (_position = 0, _length = _result.length; _position < _length; _position += 1) {
        _character = _result.charCodeAt(_position);
        if (!(_character === 0x09 ||
              (0x20 <= _character && _character <= 0x10FFFF))) {
          throwError(state, 'expected valid JSON character');
        }
      }
    } else if (PATTERN_NON_PRINTABLE.test(_result)) {
      throwError(state, 'the stream contains non-printable characters');
    }

    state.result += _result;
  }
}

function mergeMappings(state, destination, source, overridableKeys) {
  var sourceKeys, key, index, quantity;

  if (!common.isObject(source)) {
    throwError(state, 'cannot merge mappings; the provided source object is unacceptable');
  }

  sourceKeys = Object.keys(source);

  for (index = 0, quantity = sourceKeys.length; index < quantity; index += 1) {
    key = sourceKeys[index];

    if (!_hasOwnProperty$1.call(destination, key)) {
      destination[key] = source[key];
      overridableKeys[key] = true;
    }
  }
}

function storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode,
  startLine, startLineStart, startPos) {

  var index, quantity;

  // The output is a plain object here, so keys can only be strings.
  // We need to convert keyNode to a string, but doing so can hang the process
  // (deeply nested arrays that explode exponentially using aliases).
  if (Array.isArray(keyNode)) {
    keyNode = Array.prototype.slice.call(keyNode);

    for (index = 0, quantity = keyNode.length; index < quantity; index += 1) {
      if (Array.isArray(keyNode[index])) {
        throwError(state, 'nested arrays are not supported inside keys');
      }

      if (typeof keyNode === 'object' && _class(keyNode[index]) === '[object Object]') {
        keyNode[index] = '[object Object]';
      }
    }
  }

  // Avoid code execution in load() via toString property
  // (still use its own toString for arrays, timestamps,
  // and whatever user schema extensions happen to have @@toStringTag)
  if (typeof keyNode === 'object' && _class(keyNode) === '[object Object]') {
    keyNode = '[object Object]';
  }


  keyNode = String(keyNode);

  if (_result === null) {
    _result = {};
  }

  if (keyTag === 'tag:yaml.org,2002:merge') {
    if (Array.isArray(valueNode)) {
      for (index = 0, quantity = valueNode.length; index < quantity; index += 1) {
        mergeMappings(state, _result, valueNode[index], overridableKeys);
      }
    } else {
      mergeMappings(state, _result, valueNode, overridableKeys);
    }
  } else {
    if (!state.json &&
        !_hasOwnProperty$1.call(overridableKeys, keyNode) &&
        _hasOwnProperty$1.call(_result, keyNode)) {
      state.line = startLine || state.line;
      state.lineStart = startLineStart || state.lineStart;
      state.position = startPos || state.position;
      throwError(state, 'duplicated mapping key');
    }

    // used for this specific key only because Object.defineProperty is slow
    if (keyNode === '__proto__') {
      Object.defineProperty(_result, keyNode, {
        configurable: true,
        enumerable: true,
        writable: true,
        value: valueNode
      });
    } else {
      _result[keyNode] = valueNode;
    }
    delete overridableKeys[keyNode];
  }

  return _result;
}

function readLineBreak(state) {
  var ch;

  ch = state.input.charCodeAt(state.position);

  if (ch === 0x0A/* LF */) {
    state.position++;
  } else if (ch === 0x0D/* CR */) {
    state.position++;
    if (state.input.charCodeAt(state.position) === 0x0A/* LF */) {
      state.position++;
    }
  } else {
    throwError(state, 'a line break is expected');
  }

  state.line += 1;
  state.lineStart = state.position;
  state.firstTabInLine = -1;
}

function skipSeparationSpace(state, allowComments, checkIndent) {
  var lineBreaks = 0,
      ch = state.input.charCodeAt(state.position);

  while (ch !== 0) {
    while (is_WHITE_SPACE(ch)) {
      if (ch === 0x09/* Tab */ && state.firstTabInLine === -1) {
        state.firstTabInLine = state.position;
      }
      ch = state.input.charCodeAt(++state.position);
    }

    if (allowComments && ch === 0x23/* # */) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (ch !== 0x0A/* LF */ && ch !== 0x0D/* CR */ && ch !== 0);
    }

    if (is_EOL(ch)) {
      readLineBreak(state);

      ch = state.input.charCodeAt(state.position);
      lineBreaks++;
      state.lineIndent = 0;

      while (ch === 0x20/* Space */) {
        state.lineIndent++;
        ch = state.input.charCodeAt(++state.position);
      }
    } else {
      break;
    }
  }

  if (checkIndent !== -1 && lineBreaks !== 0 && state.lineIndent < checkIndent) {
    throwWarning(state, 'deficient indentation');
  }

  return lineBreaks;
}

function testDocumentSeparator(state) {
  var _position = state.position,
      ch;

  ch = state.input.charCodeAt(_position);

  // Condition state.position === state.lineStart is tested
  // in parent on each call, for efficiency. No needs to test here again.
  if ((ch === 0x2D/* - */ || ch === 0x2E/* . */) &&
      ch === state.input.charCodeAt(_position + 1) &&
      ch === state.input.charCodeAt(_position + 2)) {

    _position += 3;

    ch = state.input.charCodeAt(_position);

    if (ch === 0 || is_WS_OR_EOL(ch)) {
      return true;
    }
  }

  return false;
}

function writeFoldedLines(state, count) {
  if (count === 1) {
    state.result += ' ';
  } else if (count > 1) {
    state.result += common.repeat('\n', count - 1);
  }
}


function readPlainScalar(state, nodeIndent, withinFlowCollection) {
  var preceding,
      following,
      captureStart,
      captureEnd,
      hasPendingContent,
      _line,
      _lineStart,
      _lineIndent,
      _kind = state.kind,
      _result = state.result,
      ch;

  ch = state.input.charCodeAt(state.position);

  if (is_WS_OR_EOL(ch)      ||
      is_FLOW_INDICATOR(ch) ||
      ch === 0x23/* # */    ||
      ch === 0x26/* & */    ||
      ch === 0x2A/* * */    ||
      ch === 0x21/* ! */    ||
      ch === 0x7C/* | */    ||
      ch === 0x3E/* > */    ||
      ch === 0x27/* ' */    ||
      ch === 0x22/* " */    ||
      ch === 0x25/* % */    ||
      ch === 0x40/* @ */    ||
      ch === 0x60/* ` */) {
    return false;
  }

  if (ch === 0x3F/* ? */ || ch === 0x2D/* - */) {
    following = state.input.charCodeAt(state.position + 1);

    if (is_WS_OR_EOL(following) ||
        withinFlowCollection && is_FLOW_INDICATOR(following)) {
      return false;
    }
  }

  state.kind = 'scalar';
  state.result = '';
  captureStart = captureEnd = state.position;
  hasPendingContent = false;

  while (ch !== 0) {
    if (ch === 0x3A/* : */) {
      following = state.input.charCodeAt(state.position + 1);

      if (is_WS_OR_EOL(following) ||
          withinFlowCollection && is_FLOW_INDICATOR(following)) {
        break;
      }

    } else if (ch === 0x23/* # */) {
      preceding = state.input.charCodeAt(state.position - 1);

      if (is_WS_OR_EOL(preceding)) {
        break;
      }

    } else if ((state.position === state.lineStart && testDocumentSeparator(state)) ||
               withinFlowCollection && is_FLOW_INDICATOR(ch)) {
      break;

    } else if (is_EOL(ch)) {
      _line = state.line;
      _lineStart = state.lineStart;
      _lineIndent = state.lineIndent;
      skipSeparationSpace(state, false, -1);

      if (state.lineIndent >= nodeIndent) {
        hasPendingContent = true;
        ch = state.input.charCodeAt(state.position);
        continue;
      } else {
        state.position = captureEnd;
        state.line = _line;
        state.lineStart = _lineStart;
        state.lineIndent = _lineIndent;
        break;
      }
    }

    if (hasPendingContent) {
      captureSegment(state, captureStart, captureEnd, false);
      writeFoldedLines(state, state.line - _line);
      captureStart = captureEnd = state.position;
      hasPendingContent = false;
    }

    if (!is_WHITE_SPACE(ch)) {
      captureEnd = state.position + 1;
    }

    ch = state.input.charCodeAt(++state.position);
  }

  captureSegment(state, captureStart, captureEnd, false);

  if (state.result) {
    return true;
  }

  state.kind = _kind;
  state.result = _result;
  return false;
}

function readSingleQuotedScalar(state, nodeIndent) {
  var ch,
      captureStart, captureEnd;

  ch = state.input.charCodeAt(state.position);

  if (ch !== 0x27/* ' */) {
    return false;
  }

  state.kind = 'scalar';
  state.result = '';
  state.position++;
  captureStart = captureEnd = state.position;

  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 0x27/* ' */) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);

      if (ch === 0x27/* ' */) {
        captureStart = state.position;
        state.position++;
        captureEnd = state.position;
      } else {
        return true;
      }

    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;

    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, 'unexpected end of the document within a single quoted scalar');

    } else {
      state.position++;
      captureEnd = state.position;
    }
  }

  throwError(state, 'unexpected end of the stream within a single quoted scalar');
}

function readDoubleQuotedScalar(state, nodeIndent) {
  var captureStart,
      captureEnd,
      hexLength,
      hexResult,
      tmp,
      ch;

  ch = state.input.charCodeAt(state.position);

  if (ch !== 0x22/* " */) {
    return false;
  }

  state.kind = 'scalar';
  state.result = '';
  state.position++;
  captureStart = captureEnd = state.position;

  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 0x22/* " */) {
      captureSegment(state, captureStart, state.position, true);
      state.position++;
      return true;

    } else if (ch === 0x5C/* \ */) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);

      if (is_EOL(ch)) {
        skipSeparationSpace(state, false, nodeIndent);

        // TODO: rework to inline fn with no type cast?
      } else if (ch < 256 && simpleEscapeCheck[ch]) {
        state.result += simpleEscapeMap[ch];
        state.position++;

      } else if ((tmp = escapedHexLen(ch)) > 0) {
        hexLength = tmp;
        hexResult = 0;

        for (; hexLength > 0; hexLength--) {
          ch = state.input.charCodeAt(++state.position);

          if ((tmp = fromHexCode(ch)) >= 0) {
            hexResult = (hexResult << 4) + tmp;

          } else {
            throwError(state, 'expected hexadecimal character');
          }
        }

        state.result += charFromCodepoint(hexResult);

        state.position++;

      } else {
        throwError(state, 'unknown escape sequence');
      }

      captureStart = captureEnd = state.position;

    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;

    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, 'unexpected end of the document within a double quoted scalar');

    } else {
      state.position++;
      captureEnd = state.position;
    }
  }

  throwError(state, 'unexpected end of the stream within a double quoted scalar');
}

function readFlowCollection(state, nodeIndent) {
  var readNext = true,
      _line,
      _lineStart,
      _pos,
      _tag     = state.tag,
      _result,
      _anchor  = state.anchor,
      following,
      terminator,
      isPair,
      isExplicitPair,
      isMapping,
      overridableKeys = Object.create(null),
      keyNode,
      keyTag,
      valueNode,
      ch;

  ch = state.input.charCodeAt(state.position);

  if (ch === 0x5B/* [ */) {
    terminator = 0x5D;/* ] */
    isMapping = false;
    _result = [];
  } else if (ch === 0x7B/* { */) {
    terminator = 0x7D;/* } */
    isMapping = true;
    _result = {};
  } else {
    return false;
  }

  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }

  ch = state.input.charCodeAt(++state.position);

  while (ch !== 0) {
    skipSeparationSpace(state, true, nodeIndent);

    ch = state.input.charCodeAt(state.position);

    if (ch === terminator) {
      state.position++;
      state.tag = _tag;
      state.anchor = _anchor;
      state.kind = isMapping ? 'mapping' : 'sequence';
      state.result = _result;
      return true;
    } else if (!readNext) {
      throwError(state, 'missed comma between flow collection entries');
    } else if (ch === 0x2C/* , */) {
      // "flow collection entries can never be completely empty", as per YAML 1.2, section 7.4
      throwError(state, "expected the node content, but found ','");
    }

    keyTag = keyNode = valueNode = null;
    isPair = isExplicitPair = false;

    if (ch === 0x3F/* ? */) {
      following = state.input.charCodeAt(state.position + 1);

      if (is_WS_OR_EOL(following)) {
        isPair = isExplicitPair = true;
        state.position++;
        skipSeparationSpace(state, true, nodeIndent);
      }
    }

    _line = state.line; // Save the current line.
    _lineStart = state.lineStart;
    _pos = state.position;
    composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
    keyTag = state.tag;
    keyNode = state.result;
    skipSeparationSpace(state, true, nodeIndent);

    ch = state.input.charCodeAt(state.position);

    if ((isExplicitPair || state.line === _line) && ch === 0x3A/* : */) {
      isPair = true;
      ch = state.input.charCodeAt(++state.position);
      skipSeparationSpace(state, true, nodeIndent);
      composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
      valueNode = state.result;
    }

    if (isMapping) {
      storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos);
    } else if (isPair) {
      _result.push(storeMappingPair(state, null, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos));
    } else {
      _result.push(keyNode);
    }

    skipSeparationSpace(state, true, nodeIndent);

    ch = state.input.charCodeAt(state.position);

    if (ch === 0x2C/* , */) {
      readNext = true;
      ch = state.input.charCodeAt(++state.position);
    } else {
      readNext = false;
    }
  }

  throwError(state, 'unexpected end of the stream within a flow collection');
}

function readBlockScalar(state, nodeIndent) {
  var captureStart,
      folding,
      chomping       = CHOMPING_CLIP,
      didReadContent = false,
      detectedIndent = false,
      textIndent     = nodeIndent,
      emptyLines     = 0,
      atMoreIndented = false,
      tmp,
      ch;

  ch = state.input.charCodeAt(state.position);

  if (ch === 0x7C/* | */) {
    folding = false;
  } else if (ch === 0x3E/* > */) {
    folding = true;
  } else {
    return false;
  }

  state.kind = 'scalar';
  state.result = '';

  while (ch !== 0) {
    ch = state.input.charCodeAt(++state.position);

    if (ch === 0x2B/* + */ || ch === 0x2D/* - */) {
      if (CHOMPING_CLIP === chomping) {
        chomping = (ch === 0x2B/* + */) ? CHOMPING_KEEP : CHOMPING_STRIP;
      } else {
        throwError(state, 'repeat of a chomping mode identifier');
      }

    } else if ((tmp = fromDecimalCode(ch)) >= 0) {
      if (tmp === 0) {
        throwError(state, 'bad explicit indentation width of a block scalar; it cannot be less than one');
      } else if (!detectedIndent) {
        textIndent = nodeIndent + tmp - 1;
        detectedIndent = true;
      } else {
        throwError(state, 'repeat of an indentation width identifier');
      }

    } else {
      break;
    }
  }

  if (is_WHITE_SPACE(ch)) {
    do { ch = state.input.charCodeAt(++state.position); }
    while (is_WHITE_SPACE(ch));

    if (ch === 0x23/* # */) {
      do { ch = state.input.charCodeAt(++state.position); }
      while (!is_EOL(ch) && (ch !== 0));
    }
  }

  while (ch !== 0) {
    readLineBreak(state);
    state.lineIndent = 0;

    ch = state.input.charCodeAt(state.position);

    while ((!detectedIndent || state.lineIndent < textIndent) &&
           (ch === 0x20/* Space */)) {
      state.lineIndent++;
      ch = state.input.charCodeAt(++state.position);
    }

    if (!detectedIndent && state.lineIndent > textIndent) {
      textIndent = state.lineIndent;
    }

    if (is_EOL(ch)) {
      emptyLines++;
      continue;
    }

    // End of the scalar.
    if (state.lineIndent < textIndent) {

      // Perform the chomping.
      if (chomping === CHOMPING_KEEP) {
        state.result += common.repeat('\n', didReadContent ? 1 + emptyLines : emptyLines);
      } else if (chomping === CHOMPING_CLIP) {
        if (didReadContent) { // i.e. only if the scalar is not empty.
          state.result += '\n';
        }
      }

      // Break this `while` cycle and go to the funciton's epilogue.
      break;
    }

    // Folded style: use fancy rules to handle line breaks.
    if (folding) {

      // Lines starting with white space characters (more-indented lines) are not folded.
      if (is_WHITE_SPACE(ch)) {
        atMoreIndented = true;
        // except for the first content line (cf. Example 8.1)
        state.result += common.repeat('\n', didReadContent ? 1 + emptyLines : emptyLines);

      // End of more-indented block.
      } else if (atMoreIndented) {
        atMoreIndented = false;
        state.result += common.repeat('\n', emptyLines + 1);

      // Just one line break - perceive as the same line.
      } else if (emptyLines === 0) {
        if (didReadContent) { // i.e. only if we have already read some scalar content.
          state.result += ' ';
        }

      // Several line breaks - perceive as different lines.
      } else {
        state.result += common.repeat('\n', emptyLines);
      }

    // Literal style: just add exact number of line breaks between content lines.
    } else {
      // Keep all line breaks except the header line break.
      state.result += common.repeat('\n', didReadContent ? 1 + emptyLines : emptyLines);
    }

    didReadContent = true;
    detectedIndent = true;
    emptyLines = 0;
    captureStart = state.position;

    while (!is_EOL(ch) && (ch !== 0)) {
      ch = state.input.charCodeAt(++state.position);
    }

    captureSegment(state, captureStart, state.position, false);
  }

  return true;
}

function readBlockSequence(state, nodeIndent) {
  var _line,
      _tag      = state.tag,
      _anchor   = state.anchor,
      _result   = [],
      following,
      detected  = false,
      ch;

  // there is a leading tab before this token, so it can't be a block sequence/mapping;
  // it can still be flow sequence/mapping or a scalar
  if (state.firstTabInLine !== -1) return false;

  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }

  ch = state.input.charCodeAt(state.position);

  while (ch !== 0) {
    if (state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, 'tab characters must not be used in indentation');
    }

    if (ch !== 0x2D/* - */) {
      break;
    }

    following = state.input.charCodeAt(state.position + 1);

    if (!is_WS_OR_EOL(following)) {
      break;
    }

    detected = true;
    state.position++;

    if (skipSeparationSpace(state, true, -1)) {
      if (state.lineIndent <= nodeIndent) {
        _result.push(null);
        ch = state.input.charCodeAt(state.position);
        continue;
      }
    }

    _line = state.line;
    composeNode(state, nodeIndent, CONTEXT_BLOCK_IN, false, true);
    _result.push(state.result);
    skipSeparationSpace(state, true, -1);

    ch = state.input.charCodeAt(state.position);

    if ((state.line === _line || state.lineIndent > nodeIndent) && (ch !== 0)) {
      throwError(state, 'bad indentation of a sequence entry');
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }

  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = 'sequence';
    state.result = _result;
    return true;
  }
  return false;
}

function readBlockMapping(state, nodeIndent, flowIndent) {
  var following,
      allowCompact,
      _line,
      _keyLine,
      _keyLineStart,
      _keyPos,
      _tag          = state.tag,
      _anchor       = state.anchor,
      _result       = {},
      overridableKeys = Object.create(null),
      keyTag        = null,
      keyNode       = null,
      valueNode     = null,
      atExplicitKey = false,
      detected      = false,
      ch;

  // there is a leading tab before this token, so it can't be a block sequence/mapping;
  // it can still be flow sequence/mapping or a scalar
  if (state.firstTabInLine !== -1) return false;

  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }

  ch = state.input.charCodeAt(state.position);

  while (ch !== 0) {
    if (!atExplicitKey && state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, 'tab characters must not be used in indentation');
    }

    following = state.input.charCodeAt(state.position + 1);
    _line = state.line; // Save the current line.

    //
    // Explicit notation case. There are two separate blocks:
    // first for the key (denoted by "?") and second for the value (denoted by ":")
    //
    if ((ch === 0x3F/* ? */ || ch === 0x3A/* : */) && is_WS_OR_EOL(following)) {

      if (ch === 0x3F/* ? */) {
        if (atExplicitKey) {
          storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
          keyTag = keyNode = valueNode = null;
        }

        detected = true;
        atExplicitKey = true;
        allowCompact = true;

      } else if (atExplicitKey) {
        // i.e. 0x3A/* : */ === character after the explicit key.
        atExplicitKey = false;
        allowCompact = true;

      } else {
        throwError(state, 'incomplete explicit mapping pair; a key node is missed; or followed by a non-tabulated empty line');
      }

      state.position += 1;
      ch = following;

    //
    // Implicit notation case. Flow-style node as the key first, then ":", and the value.
    //
    } else {
      _keyLine = state.line;
      _keyLineStart = state.lineStart;
      _keyPos = state.position;

      if (!composeNode(state, flowIndent, CONTEXT_FLOW_OUT, false, true)) {
        // Neither implicit nor explicit notation.
        // Reading is done. Go to the epilogue.
        break;
      }

      if (state.line === _line) {
        ch = state.input.charCodeAt(state.position);

        while (is_WHITE_SPACE(ch)) {
          ch = state.input.charCodeAt(++state.position);
        }

        if (ch === 0x3A/* : */) {
          ch = state.input.charCodeAt(++state.position);

          if (!is_WS_OR_EOL(ch)) {
            throwError(state, 'a whitespace character is expected after the key-value separator within a block mapping');
          }

          if (atExplicitKey) {
            storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
            keyTag = keyNode = valueNode = null;
          }

          detected = true;
          atExplicitKey = false;
          allowCompact = false;
          keyTag = state.tag;
          keyNode = state.result;

        } else if (detected) {
          throwError(state, 'can not read an implicit mapping pair; a colon is missed');

        } else {
          state.tag = _tag;
          state.anchor = _anchor;
          return true; // Keep the result of `composeNode`.
        }

      } else if (detected) {
        throwError(state, 'can not read a block mapping entry; a multiline key may not be an implicit key');

      } else {
        state.tag = _tag;
        state.anchor = _anchor;
        return true; // Keep the result of `composeNode`.
      }
    }

    //
    // Common reading code for both explicit and implicit notations.
    //
    if (state.line === _line || state.lineIndent > nodeIndent) {
      if (atExplicitKey) {
        _keyLine = state.line;
        _keyLineStart = state.lineStart;
        _keyPos = state.position;
      }

      if (composeNode(state, nodeIndent, CONTEXT_BLOCK_OUT, true, allowCompact)) {
        if (atExplicitKey) {
          keyNode = state.result;
        } else {
          valueNode = state.result;
        }
      }

      if (!atExplicitKey) {
        storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _keyLine, _keyLineStart, _keyPos);
        keyTag = keyNode = valueNode = null;
      }

      skipSeparationSpace(state, true, -1);
      ch = state.input.charCodeAt(state.position);
    }

    if ((state.line === _line || state.lineIndent > nodeIndent) && (ch !== 0)) {
      throwError(state, 'bad indentation of a mapping entry');
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }

  //
  // Epilogue.
  //

  // Special case: last mapping's node contains only the key in explicit notation.
  if (atExplicitKey) {
    storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
  }

  // Expose the resulting mapping.
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = 'mapping';
    state.result = _result;
  }

  return detected;
}

function readTagProperty(state) {
  var _position,
      isVerbatim = false,
      isNamed    = false,
      tagHandle,
      tagName,
      ch;

  ch = state.input.charCodeAt(state.position);

  if (ch !== 0x21/* ! */) return false;

  if (state.tag !== null) {
    throwError(state, 'duplication of a tag property');
  }

  ch = state.input.charCodeAt(++state.position);

  if (ch === 0x3C/* < */) {
    isVerbatim = true;
    ch = state.input.charCodeAt(++state.position);

  } else if (ch === 0x21/* ! */) {
    isNamed = true;
    tagHandle = '!!';
    ch = state.input.charCodeAt(++state.position);

  } else {
    tagHandle = '!';
  }

  _position = state.position;

  if (isVerbatim) {
    do { ch = state.input.charCodeAt(++state.position); }
    while (ch !== 0 && ch !== 0x3E/* > */);

    if (state.position < state.length) {
      tagName = state.input.slice(_position, state.position);
      ch = state.input.charCodeAt(++state.position);
    } else {
      throwError(state, 'unexpected end of the stream within a verbatim tag');
    }
  } else {
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {

      if (ch === 0x21/* ! */) {
        if (!isNamed) {
          tagHandle = state.input.slice(_position - 1, state.position + 1);

          if (!PATTERN_TAG_HANDLE.test(tagHandle)) {
            throwError(state, 'named tag handle cannot contain such characters');
          }

          isNamed = true;
          _position = state.position + 1;
        } else {
          throwError(state, 'tag suffix cannot contain exclamation marks');
        }
      }

      ch = state.input.charCodeAt(++state.position);
    }

    tagName = state.input.slice(_position, state.position);

    if (PATTERN_FLOW_INDICATORS.test(tagName)) {
      throwError(state, 'tag suffix cannot contain flow indicator characters');
    }
  }

  if (tagName && !PATTERN_TAG_URI.test(tagName)) {
    throwError(state, 'tag name cannot contain such characters: ' + tagName);
  }

  try {
    tagName = decodeURIComponent(tagName);
  } catch (err) {
    throwError(state, 'tag name is malformed: ' + tagName);
  }

  if (isVerbatim) {
    state.tag = tagName;

  } else if (_hasOwnProperty$1.call(state.tagMap, tagHandle)) {
    state.tag = state.tagMap[tagHandle] + tagName;

  } else if (tagHandle === '!') {
    state.tag = '!' + tagName;

  } else if (tagHandle === '!!') {
    state.tag = 'tag:yaml.org,2002:' + tagName;

  } else {
    throwError(state, 'undeclared tag handle "' + tagHandle + '"');
  }

  return true;
}

function readAnchorProperty(state) {
  var _position,
      ch;

  ch = state.input.charCodeAt(state.position);

  if (ch !== 0x26/* & */) return false;

  if (state.anchor !== null) {
    throwError(state, 'duplication of an anchor property');
  }

  ch = state.input.charCodeAt(++state.position);
  _position = state.position;

  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }

  if (state.position === _position) {
    throwError(state, 'name of an anchor node must contain at least one character');
  }

  state.anchor = state.input.slice(_position, state.position);
  return true;
}

function readAlias(state) {
  var _position, alias,
      ch;

  ch = state.input.charCodeAt(state.position);

  if (ch !== 0x2A/* * */) return false;

  ch = state.input.charCodeAt(++state.position);
  _position = state.position;

  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }

  if (state.position === _position) {
    throwError(state, 'name of an alias node must contain at least one character');
  }

  alias = state.input.slice(_position, state.position);

  if (!_hasOwnProperty$1.call(state.anchorMap, alias)) {
    throwError(state, 'unidentified alias "' + alias + '"');
  }

  state.result = state.anchorMap[alias];
  skipSeparationSpace(state, true, -1);
  return true;
}

function composeNode(state, parentIndent, nodeContext, allowToSeek, allowCompact) {
  var allowBlockStyles,
      allowBlockScalars,
      allowBlockCollections,
      indentStatus = 1, // 1: this>parent, 0: this=parent, -1: this<parent
      atNewLine  = false,
      hasContent = false,
      typeIndex,
      typeQuantity,
      typeList,
      type,
      flowIndent,
      blockIndent;

  if (state.listener !== null) {
    state.listener('open', state);
  }

  state.tag    = null;
  state.anchor = null;
  state.kind   = null;
  state.result = null;

  allowBlockStyles = allowBlockScalars = allowBlockCollections =
    CONTEXT_BLOCK_OUT === nodeContext ||
    CONTEXT_BLOCK_IN  === nodeContext;

  if (allowToSeek) {
    if (skipSeparationSpace(state, true, -1)) {
      atNewLine = true;

      if (state.lineIndent > parentIndent) {
        indentStatus = 1;
      } else if (state.lineIndent === parentIndent) {
        indentStatus = 0;
      } else if (state.lineIndent < parentIndent) {
        indentStatus = -1;
      }
    }
  }

  if (indentStatus === 1) {
    while (readTagProperty(state) || readAnchorProperty(state)) {
      if (skipSeparationSpace(state, true, -1)) {
        atNewLine = true;
        allowBlockCollections = allowBlockStyles;

        if (state.lineIndent > parentIndent) {
          indentStatus = 1;
        } else if (state.lineIndent === parentIndent) {
          indentStatus = 0;
        } else if (state.lineIndent < parentIndent) {
          indentStatus = -1;
        }
      } else {
        allowBlockCollections = false;
      }
    }
  }

  if (allowBlockCollections) {
    allowBlockCollections = atNewLine || allowCompact;
  }

  if (indentStatus === 1 || CONTEXT_BLOCK_OUT === nodeContext) {
    if (CONTEXT_FLOW_IN === nodeContext || CONTEXT_FLOW_OUT === nodeContext) {
      flowIndent = parentIndent;
    } else {
      flowIndent = parentIndent + 1;
    }

    blockIndent = state.position - state.lineStart;

    if (indentStatus === 1) {
      if (allowBlockCollections &&
          (readBlockSequence(state, blockIndent) ||
           readBlockMapping(state, blockIndent, flowIndent)) ||
          readFlowCollection(state, flowIndent)) {
        hasContent = true;
      } else {
        if ((allowBlockScalars && readBlockScalar(state, flowIndent)) ||
            readSingleQuotedScalar(state, flowIndent) ||
            readDoubleQuotedScalar(state, flowIndent)) {
          hasContent = true;

        } else if (readAlias(state)) {
          hasContent = true;

          if (state.tag !== null || state.anchor !== null) {
            throwError(state, 'alias node should not have any properties');
          }

        } else if (readPlainScalar(state, flowIndent, CONTEXT_FLOW_IN === nodeContext)) {
          hasContent = true;

          if (state.tag === null) {
            state.tag = '?';
          }
        }

        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
      }
    } else if (indentStatus === 0) {
      // Special case: block sequences are allowed to have same indentation level as the parent.
      // http://www.yaml.org/spec/1.2/spec.html#id2799784
      hasContent = allowBlockCollections && readBlockSequence(state, blockIndent);
    }
  }

  if (state.tag === null) {
    if (state.anchor !== null) {
      state.anchorMap[state.anchor] = state.result;
    }

  } else if (state.tag === '?') {
    // Implicit resolving is not allowed for non-scalar types, and '?'
    // non-specific tag is only automatically assigned to plain scalars.
    //
    // We only need to check kind conformity in case user explicitly assigns '?'
    // tag, for example like this: "!<?> [0]"
    //
    if (state.result !== null && state.kind !== 'scalar') {
      throwError(state, 'unacceptable node kind for !<?> tag; it should be "scalar", not "' + state.kind + '"');
    }

    for (typeIndex = 0, typeQuantity = state.implicitTypes.length; typeIndex < typeQuantity; typeIndex += 1) {
      type = state.implicitTypes[typeIndex];

      if (type.resolve(state.result)) { // `state.result` updated in resolver if matched
        state.result = type.construct(state.result);
        state.tag = type.tag;
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
        break;
      }
    }
  } else if (state.tag !== '!') {
    if (_hasOwnProperty$1.call(state.typeMap[state.kind || 'fallback'], state.tag)) {
      type = state.typeMap[state.kind || 'fallback'][state.tag];
    } else {
      // looking for multi type
      type = null;
      typeList = state.typeMap.multi[state.kind || 'fallback'];

      for (typeIndex = 0, typeQuantity = typeList.length; typeIndex < typeQuantity; typeIndex += 1) {
        if (state.tag.slice(0, typeList[typeIndex].tag.length) === typeList[typeIndex].tag) {
          type = typeList[typeIndex];
          break;
        }
      }
    }

    if (!type) {
      throwError(state, 'unknown tag !<' + state.tag + '>');
    }

    if (state.result !== null && type.kind !== state.kind) {
      throwError(state, 'unacceptable node kind for !<' + state.tag + '> tag; it should be "' + type.kind + '", not "' + state.kind + '"');
    }

    if (!type.resolve(state.result, state.tag)) { // `state.result` updated in resolver if matched
      throwError(state, 'cannot resolve a node with !<' + state.tag + '> explicit tag');
    } else {
      state.result = type.construct(state.result, state.tag);
      if (state.anchor !== null) {
        state.anchorMap[state.anchor] = state.result;
      }
    }
  }

  if (state.listener !== null) {
    state.listener('close', state);
  }
  return state.tag !== null ||  state.anchor !== null || hasContent;
}

function readDocument(state) {
  var documentStart = state.position,
      _position,
      directiveName,
      directiveArgs,
      hasDirectives = false,
      ch;

  state.version = null;
  state.checkLineBreaks = state.legacy;
  state.tagMap = Object.create(null);
  state.anchorMap = Object.create(null);

  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    skipSeparationSpace(state, true, -1);

    ch = state.input.charCodeAt(state.position);

    if (state.lineIndent > 0 || ch !== 0x25/* % */) {
      break;
    }

    hasDirectives = true;
    ch = state.input.charCodeAt(++state.position);
    _position = state.position;

    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      ch = state.input.charCodeAt(++state.position);
    }

    directiveName = state.input.slice(_position, state.position);
    directiveArgs = [];

    if (directiveName.length < 1) {
      throwError(state, 'directive name must not be less than one character in length');
    }

    while (ch !== 0) {
      while (is_WHITE_SPACE(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }

      if (ch === 0x23/* # */) {
        do { ch = state.input.charCodeAt(++state.position); }
        while (ch !== 0 && !is_EOL(ch));
        break;
      }

      if (is_EOL(ch)) break;

      _position = state.position;

      while (ch !== 0 && !is_WS_OR_EOL(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }

      directiveArgs.push(state.input.slice(_position, state.position));
    }

    if (ch !== 0) readLineBreak(state);

    if (_hasOwnProperty$1.call(directiveHandlers, directiveName)) {
      directiveHandlers[directiveName](state, directiveName, directiveArgs);
    } else {
      throwWarning(state, 'unknown document directive "' + directiveName + '"');
    }
  }

  skipSeparationSpace(state, true, -1);

  if (state.lineIndent === 0 &&
      state.input.charCodeAt(state.position)     === 0x2D/* - */ &&
      state.input.charCodeAt(state.position + 1) === 0x2D/* - */ &&
      state.input.charCodeAt(state.position + 2) === 0x2D/* - */) {
    state.position += 3;
    skipSeparationSpace(state, true, -1);

  } else if (hasDirectives) {
    throwError(state, 'directives end mark is expected');
  }

  composeNode(state, state.lineIndent - 1, CONTEXT_BLOCK_OUT, false, true);
  skipSeparationSpace(state, true, -1);

  if (state.checkLineBreaks &&
      PATTERN_NON_ASCII_LINE_BREAKS.test(state.input.slice(documentStart, state.position))) {
    throwWarning(state, 'non-ASCII line breaks are interpreted as content');
  }

  state.documents.push(state.result);

  if (state.position === state.lineStart && testDocumentSeparator(state)) {

    if (state.input.charCodeAt(state.position) === 0x2E/* . */) {
      state.position += 3;
      skipSeparationSpace(state, true, -1);
    }
    return;
  }

  if (state.position < (state.length - 1)) {
    throwError(state, 'end of the stream or a document separator is expected');
  } else {
    return;
  }
}


function loadDocuments(input, options) {
  input = String(input);
  options = options || {};

  if (input.length !== 0) {

    // Add tailing `\n` if not exists
    if (input.charCodeAt(input.length - 1) !== 0x0A/* LF */ &&
        input.charCodeAt(input.length - 1) !== 0x0D/* CR */) {
      input += '\n';
    }

    // Strip BOM
    if (input.charCodeAt(0) === 0xFEFF) {
      input = input.slice(1);
    }
  }

  var state = new State$1(input, options);

  var nullpos = input.indexOf('\0');

  if (nullpos !== -1) {
    state.position = nullpos;
    throwError(state, 'null byte is not allowed in input');
  }

  // Use 0 as string terminator. That significantly simplifies bounds check.
  state.input += '\0';

  while (state.input.charCodeAt(state.position) === 0x20/* Space */) {
    state.lineIndent += 1;
    state.position += 1;
  }

  while (state.position < (state.length - 1)) {
    readDocument(state);
  }

  return state.documents;
}


function loadAll$1(input, iterator, options) {
  if (iterator !== null && typeof iterator === 'object' && typeof options === 'undefined') {
    options = iterator;
    iterator = null;
  }

  var documents = loadDocuments(input, options);

  if (typeof iterator !== 'function') {
    return documents;
  }

  for (var index = 0, length = documents.length; index < length; index += 1) {
    iterator(documents[index]);
  }
}


function load$1(input, options) {
  var documents = loadDocuments(input, options);

  if (documents.length === 0) {
    /*eslint-disable no-undefined*/
    return undefined;
  } else if (documents.length === 1) {
    return documents[0];
  }
  throw new exception('expected a single document in the stream, but found more');
}


var loadAll_1 = loadAll$1;
var load_1    = load$1;

var loader = {
	loadAll: loadAll_1,
	load: load_1
};

/*eslint-disable no-use-before-define*/





var _toString       = Object.prototype.toString;
var _hasOwnProperty = Object.prototype.hasOwnProperty;

var CHAR_BOM                  = 0xFEFF;
var CHAR_TAB                  = 0x09; /* Tab */
var CHAR_LINE_FEED            = 0x0A; /* LF */
var CHAR_CARRIAGE_RETURN      = 0x0D; /* CR */
var CHAR_SPACE                = 0x20; /* Space */
var CHAR_EXCLAMATION          = 0x21; /* ! */
var CHAR_DOUBLE_QUOTE         = 0x22; /* " */
var CHAR_SHARP                = 0x23; /* # */
var CHAR_PERCENT              = 0x25; /* % */
var CHAR_AMPERSAND            = 0x26; /* & */
var CHAR_SINGLE_QUOTE         = 0x27; /* ' */
var CHAR_ASTERISK             = 0x2A; /* * */
var CHAR_COMMA                = 0x2C; /* , */
var CHAR_MINUS                = 0x2D; /* - */
var CHAR_COLON                = 0x3A; /* : */
var CHAR_EQUALS               = 0x3D; /* = */
var CHAR_GREATER_THAN         = 0x3E; /* > */
var CHAR_QUESTION             = 0x3F; /* ? */
var CHAR_COMMERCIAL_AT        = 0x40; /* @ */
var CHAR_LEFT_SQUARE_BRACKET  = 0x5B; /* [ */
var CHAR_RIGHT_SQUARE_BRACKET = 0x5D; /* ] */
var CHAR_GRAVE_ACCENT         = 0x60; /* ` */
var CHAR_LEFT_CURLY_BRACKET   = 0x7B; /* { */
var CHAR_VERTICAL_LINE        = 0x7C; /* | */
var CHAR_RIGHT_CURLY_BRACKET  = 0x7D; /* } */

var ESCAPE_SEQUENCES = {};

ESCAPE_SEQUENCES[0x00]   = '\\0';
ESCAPE_SEQUENCES[0x07]   = '\\a';
ESCAPE_SEQUENCES[0x08]   = '\\b';
ESCAPE_SEQUENCES[0x09]   = '\\t';
ESCAPE_SEQUENCES[0x0A]   = '\\n';
ESCAPE_SEQUENCES[0x0B]   = '\\v';
ESCAPE_SEQUENCES[0x0C]   = '\\f';
ESCAPE_SEQUENCES[0x0D]   = '\\r';
ESCAPE_SEQUENCES[0x1B]   = '\\e';
ESCAPE_SEQUENCES[0x22]   = '\\"';
ESCAPE_SEQUENCES[0x5C]   = '\\\\';
ESCAPE_SEQUENCES[0x85]   = '\\N';
ESCAPE_SEQUENCES[0xA0]   = '\\_';
ESCAPE_SEQUENCES[0x2028] = '\\L';
ESCAPE_SEQUENCES[0x2029] = '\\P';

var DEPRECATED_BOOLEANS_SYNTAX = [
  'y', 'Y', 'yes', 'Yes', 'YES', 'on', 'On', 'ON',
  'n', 'N', 'no', 'No', 'NO', 'off', 'Off', 'OFF'
];

var DEPRECATED_BASE60_SYNTAX = /^[-+]?[0-9_]+(?::[0-9_]+)+(?:\.[0-9_]*)?$/;

function compileStyleMap(schema, map) {
  var result, keys, index, length, tag, style, type;

  if (map === null) return {};

  result = {};
  keys = Object.keys(map);

  for (index = 0, length = keys.length; index < length; index += 1) {
    tag = keys[index];
    style = String(map[tag]);

    if (tag.slice(0, 2) === '!!') {
      tag = 'tag:yaml.org,2002:' + tag.slice(2);
    }
    type = schema.compiledTypeMap['fallback'][tag];

    if (type && _hasOwnProperty.call(type.styleAliases, style)) {
      style = type.styleAliases[style];
    }

    result[tag] = style;
  }

  return result;
}

function encodeHex(character) {
  var string, handle, length;

  string = character.toString(16).toUpperCase();

  if (character <= 0xFF) {
    handle = 'x';
    length = 2;
  } else if (character <= 0xFFFF) {
    handle = 'u';
    length = 4;
  } else if (character <= 0xFFFFFFFF) {
    handle = 'U';
    length = 8;
  } else {
    throw new exception('code point within a string may not be greater than 0xFFFFFFFF');
  }

  return '\\' + handle + common.repeat('0', length - string.length) + string;
}


var QUOTING_TYPE_SINGLE = 1,
    QUOTING_TYPE_DOUBLE = 2;

function State(options) {
  this.schema        = options['schema'] || _default;
  this.indent        = Math.max(1, (options['indent'] || 2));
  this.noArrayIndent = options['noArrayIndent'] || false;
  this.skipInvalid   = options['skipInvalid'] || false;
  this.flowLevel     = (common.isNothing(options['flowLevel']) ? -1 : options['flowLevel']);
  this.styleMap      = compileStyleMap(this.schema, options['styles'] || null);
  this.sortKeys      = options['sortKeys'] || false;
  this.lineWidth     = options['lineWidth'] || 80;
  this.noRefs        = options['noRefs'] || false;
  this.noCompatMode  = options['noCompatMode'] || false;
  this.condenseFlow  = options['condenseFlow'] || false;
  this.quotingType   = options['quotingType'] === '"' ? QUOTING_TYPE_DOUBLE : QUOTING_TYPE_SINGLE;
  this.forceQuotes   = options['forceQuotes'] || false;
  this.replacer      = typeof options['replacer'] === 'function' ? options['replacer'] : null;

  this.implicitTypes = this.schema.compiledImplicit;
  this.explicitTypes = this.schema.compiledExplicit;

  this.tag = null;
  this.result = '';

  this.duplicates = [];
  this.usedDuplicates = null;
}

// Indents every line in a string. Empty lines (\n only) are not indented.
function indentString(string, spaces) {
  var ind = common.repeat(' ', spaces),
      position = 0,
      next = -1,
      result = '',
      line,
      length = string.length;

  while (position < length) {
    next = string.indexOf('\n', position);
    if (next === -1) {
      line = string.slice(position);
      position = length;
    } else {
      line = string.slice(position, next + 1);
      position = next + 1;
    }

    if (line.length && line !== '\n') result += ind;

    result += line;
  }

  return result;
}

function generateNextLine(state, level) {
  return '\n' + common.repeat(' ', state.indent * level);
}

function testImplicitResolving(state, str) {
  var index, length, type;

  for (index = 0, length = state.implicitTypes.length; index < length; index += 1) {
    type = state.implicitTypes[index];

    if (type.resolve(str)) {
      return true;
    }
  }

  return false;
}

// [33] s-white ::= s-space | s-tab
function isWhitespace(c) {
  return c === CHAR_SPACE || c === CHAR_TAB;
}

// Returns true if the character can be printed without escaping.
// From YAML 1.2: "any allowed characters known to be non-printable
// should also be escaped. [However,] This isn’t mandatory"
// Derived from nb-char - \t - #x85 - #xA0 - #x2028 - #x2029.
function isPrintable(c) {
  return  (0x00020 <= c && c <= 0x00007E)
      || ((0x000A1 <= c && c <= 0x00D7FF) && c !== 0x2028 && c !== 0x2029)
      || ((0x0E000 <= c && c <= 0x00FFFD) && c !== CHAR_BOM)
      ||  (0x10000 <= c && c <= 0x10FFFF);
}

// [34] ns-char ::= nb-char - s-white
// [27] nb-char ::= c-printable - b-char - c-byte-order-mark
// [26] b-char  ::= b-line-feed | b-carriage-return
// Including s-white (for some reason, examples doesn't match specs in this aspect)
// ns-char ::= c-printable - b-line-feed - b-carriage-return - c-byte-order-mark
function isNsCharOrWhitespace(c) {
  return isPrintable(c)
    && c !== CHAR_BOM
    // - b-char
    && c !== CHAR_CARRIAGE_RETURN
    && c !== CHAR_LINE_FEED;
}

// [127]  ns-plain-safe(c) ::= c = flow-out  ⇒ ns-plain-safe-out
//                             c = flow-in   ⇒ ns-plain-safe-in
//                             c = block-key ⇒ ns-plain-safe-out
//                             c = flow-key  ⇒ ns-plain-safe-in
// [128] ns-plain-safe-out ::= ns-char
// [129]  ns-plain-safe-in ::= ns-char - c-flow-indicator
// [130]  ns-plain-char(c) ::=  ( ns-plain-safe(c) - “:” - “#” )
//                            | ( /* An ns-char preceding */ “#” )
//                            | ( “:” /* Followed by an ns-plain-safe(c) */ )
function isPlainSafe(c, prev, inblock) {
  var cIsNsCharOrWhitespace = isNsCharOrWhitespace(c);
  var cIsNsChar = cIsNsCharOrWhitespace && !isWhitespace(c);
  return (
    // ns-plain-safe
    inblock ? // c = flow-in
      cIsNsCharOrWhitespace
      : cIsNsCharOrWhitespace
        // - c-flow-indicator
        && c !== CHAR_COMMA
        && c !== CHAR_LEFT_SQUARE_BRACKET
        && c !== CHAR_RIGHT_SQUARE_BRACKET
        && c !== CHAR_LEFT_CURLY_BRACKET
        && c !== CHAR_RIGHT_CURLY_BRACKET
  )
    // ns-plain-char
    && c !== CHAR_SHARP // false on '#'
    && !(prev === CHAR_COLON && !cIsNsChar) // false on ': '
    || (isNsCharOrWhitespace(prev) && !isWhitespace(prev) && c === CHAR_SHARP) // change to true on '[^ ]#'
    || (prev === CHAR_COLON && cIsNsChar); // change to true on ':[^ ]'
}

// Simplified test for values allowed as the first character in plain style.
function isPlainSafeFirst(c) {
  // Uses a subset of ns-char - c-indicator
  // where ns-char = nb-char - s-white.
  // No support of ( ( “?” | “:” | “-” ) /* Followed by an ns-plain-safe(c)) */ ) part
  return isPrintable(c) && c !== CHAR_BOM
    && !isWhitespace(c) // - s-white
    // - (c-indicator ::=
    // “-” | “?” | “:” | “,” | “[” | “]” | “{” | “}”
    && c !== CHAR_MINUS
    && c !== CHAR_QUESTION
    && c !== CHAR_COLON
    && c !== CHAR_COMMA
    && c !== CHAR_LEFT_SQUARE_BRACKET
    && c !== CHAR_RIGHT_SQUARE_BRACKET
    && c !== CHAR_LEFT_CURLY_BRACKET
    && c !== CHAR_RIGHT_CURLY_BRACKET
    // | “#” | “&” | “*” | “!” | “|” | “=” | “>” | “'” | “"”
    && c !== CHAR_SHARP
    && c !== CHAR_AMPERSAND
    && c !== CHAR_ASTERISK
    && c !== CHAR_EXCLAMATION
    && c !== CHAR_VERTICAL_LINE
    && c !== CHAR_EQUALS
    && c !== CHAR_GREATER_THAN
    && c !== CHAR_SINGLE_QUOTE
    && c !== CHAR_DOUBLE_QUOTE
    // | “%” | “@” | “`”)
    && c !== CHAR_PERCENT
    && c !== CHAR_COMMERCIAL_AT
    && c !== CHAR_GRAVE_ACCENT;
}

// Simplified test for values allowed as the last character in plain style.
function isPlainSafeLast(c) {
  // just not whitespace or colon, it will be checked to be plain character later
  return !isWhitespace(c) && c !== CHAR_COLON;
}

// Same as 'string'.codePointAt(pos), but works in older browsers.
function codePointAt(string, pos) {
  var first = string.charCodeAt(pos), second;
  if (first >= 0xD800 && first <= 0xDBFF && pos + 1 < string.length) {
    second = string.charCodeAt(pos + 1);
    if (second >= 0xDC00 && second <= 0xDFFF) {
      // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
      return (first - 0xD800) * 0x400 + second - 0xDC00 + 0x10000;
    }
  }
  return first;
}

// Determines whether block indentation indicator is required.
function needIndentIndicator(string) {
  var leadingSpaceRe = /^\n* /;
  return leadingSpaceRe.test(string);
}

var STYLE_PLAIN   = 1,
    STYLE_SINGLE  = 2,
    STYLE_LITERAL = 3,
    STYLE_FOLDED  = 4,
    STYLE_DOUBLE  = 5;

// Determines which scalar styles are possible and returns the preferred style.
// lineWidth = -1 => no limit.
// Pre-conditions: str.length > 0.
// Post-conditions:
//    STYLE_PLAIN or STYLE_SINGLE => no \n are in the string.
//    STYLE_LITERAL => no lines are suitable for folding (or lineWidth is -1).
//    STYLE_FOLDED => a line > lineWidth and can be folded (and lineWidth != -1).
function chooseScalarStyle(string, singleLineOnly, indentPerLevel, lineWidth,
  testAmbiguousType, quotingType, forceQuotes, inblock) {

  var i;
  var char = 0;
  var prevChar = null;
  var hasLineBreak = false;
  var hasFoldableLine = false; // only checked if shouldTrackWidth
  var shouldTrackWidth = lineWidth !== -1;
  var previousLineBreak = -1; // count the first line correctly
  var plain = isPlainSafeFirst(codePointAt(string, 0))
          && isPlainSafeLast(codePointAt(string, string.length - 1));

  if (singleLineOnly || forceQuotes) {
    // Case: no block styles.
    // Check for disallowed characters to rule out plain and single.
    for (i = 0; i < string.length; char >= 0x10000 ? i += 2 : i++) {
      char = codePointAt(string, i);
      if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
  } else {
    // Case: block styles permitted.
    for (i = 0; i < string.length; char >= 0x10000 ? i += 2 : i++) {
      char = codePointAt(string, i);
      if (char === CHAR_LINE_FEED) {
        hasLineBreak = true;
        // Check if any line can be folded.
        if (shouldTrackWidth) {
          hasFoldableLine = hasFoldableLine ||
            // Foldable line = too long, and not more-indented.
            (i - previousLineBreak - 1 > lineWidth &&
             string[previousLineBreak + 1] !== ' ');
          previousLineBreak = i;
        }
      } else if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
    // in case the end is missing a \n
    hasFoldableLine = hasFoldableLine || (shouldTrackWidth &&
      (i - previousLineBreak - 1 > lineWidth &&
       string[previousLineBreak + 1] !== ' '));
  }
  // Although every style can represent \n without escaping, prefer block styles
  // for multiline, since they're more readable and they don't add empty lines.
  // Also prefer folding a super-long line.
  if (!hasLineBreak && !hasFoldableLine) {
    // Strings interpretable as another type have to be quoted;
    // e.g. the string 'true' vs. the boolean true.
    if (plain && !forceQuotes && !testAmbiguousType(string)) {
      return STYLE_PLAIN;
    }
    return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
  }
  // Edge case: block indentation indicator can only have one digit.
  if (indentPerLevel > 9 && needIndentIndicator(string)) {
    return STYLE_DOUBLE;
  }
  // At this point we know block styles are valid.
  // Prefer literal style unless we want to fold.
  if (!forceQuotes) {
    return hasFoldableLine ? STYLE_FOLDED : STYLE_LITERAL;
  }
  return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
}

// Note: line breaking/folding is implemented for only the folded style.
// NB. We drop the last trailing newline (if any) of a returned block scalar
//  since the dumper adds its own newline. This always works:
//    • No ending newline => unaffected; already using strip "-" chomping.
//    • Ending newline    => removed then restored.
//  Importantly, this keeps the "+" chomp indicator from gaining an extra line.
function writeScalar(state, string, level, iskey, inblock) {
  state.dump = (function () {
    if (string.length === 0) {
      return state.quotingType === QUOTING_TYPE_DOUBLE ? '""' : "''";
    }
    if (!state.noCompatMode) {
      if (DEPRECATED_BOOLEANS_SYNTAX.indexOf(string) !== -1 || DEPRECATED_BASE60_SYNTAX.test(string)) {
        return state.quotingType === QUOTING_TYPE_DOUBLE ? ('"' + string + '"') : ("'" + string + "'");
      }
    }

    var indent = state.indent * Math.max(1, level); // no 0-indent scalars
    // As indentation gets deeper, let the width decrease monotonically
    // to the lower bound min(state.lineWidth, 40).
    // Note that this implies
    //  state.lineWidth ≤ 40 + state.indent: width is fixed at the lower bound.
    //  state.lineWidth > 40 + state.indent: width decreases until the lower bound.
    // This behaves better than a constant minimum width which disallows narrower options,
    // or an indent threshold which causes the width to suddenly increase.
    var lineWidth = state.lineWidth === -1
      ? -1 : Math.max(Math.min(state.lineWidth, 40), state.lineWidth - indent);

    // Without knowing if keys are implicit/explicit, assume implicit for safety.
    var singleLineOnly = iskey
      // No block styles in flow mode.
      || (state.flowLevel > -1 && level >= state.flowLevel);
    function testAmbiguity(string) {
      return testImplicitResolving(state, string);
    }

    switch (chooseScalarStyle(string, singleLineOnly, state.indent, lineWidth,
      testAmbiguity, state.quotingType, state.forceQuotes && !iskey, inblock)) {

      case STYLE_PLAIN:
        return string;
      case STYLE_SINGLE:
        return "'" + string.replace(/'/g, "''") + "'";
      case STYLE_LITERAL:
        return '|' + blockHeader(string, state.indent)
          + dropEndingNewline(indentString(string, indent));
      case STYLE_FOLDED:
        return '>' + blockHeader(string, state.indent)
          + dropEndingNewline(indentString(foldString(string, lineWidth), indent));
      case STYLE_DOUBLE:
        return '"' + escapeString(string) + '"';
      default:
        throw new exception('impossible error: invalid scalar style');
    }
  }());
}

// Pre-conditions: string is valid for a block scalar, 1 <= indentPerLevel <= 9.
function blockHeader(string, indentPerLevel) {
  var indentIndicator = needIndentIndicator(string) ? String(indentPerLevel) : '';

  // note the special case: the string '\n' counts as a "trailing" empty line.
  var clip =          string[string.length - 1] === '\n';
  var keep = clip && (string[string.length - 2] === '\n' || string === '\n');
  var chomp = keep ? '+' : (clip ? '' : '-');

  return indentIndicator + chomp + '\n';
}

// (See the note for writeScalar.)
function dropEndingNewline(string) {
  return string[string.length - 1] === '\n' ? string.slice(0, -1) : string;
}

// Note: a long line without a suitable break point will exceed the width limit.
// Pre-conditions: every char in str isPrintable, str.length > 0, width > 0.
function foldString(string, width) {
  // In folded style, $k$ consecutive newlines output as $k+1$ newlines—
  // unless they're before or after a more-indented line, or at the very
  // beginning or end, in which case $k$ maps to $k$.
  // Therefore, parse each chunk as newline(s) followed by a content line.
  var lineRe = /(\n+)([^\n]*)/g;

  // first line (possibly an empty line)
  var result = (function () {
    var nextLF = string.indexOf('\n');
    nextLF = nextLF !== -1 ? nextLF : string.length;
    lineRe.lastIndex = nextLF;
    return foldLine(string.slice(0, nextLF), width);
  }());
  // If we haven't reached the first content line yet, don't add an extra \n.
  var prevMoreIndented = string[0] === '\n' || string[0] === ' ';
  var moreIndented;

  // rest of the lines
  var match;
  while ((match = lineRe.exec(string))) {
    var prefix = match[1], line = match[2];
    moreIndented = (line[0] === ' ');
    result += prefix
      + (!prevMoreIndented && !moreIndented && line !== ''
        ? '\n' : '')
      + foldLine(line, width);
    prevMoreIndented = moreIndented;
  }

  return result;
}

// Greedy line breaking.
// Picks the longest line under the limit each time,
// otherwise settles for the shortest line over the limit.
// NB. More-indented lines *cannot* be folded, as that would add an extra \n.
function foldLine(line, width) {
  if (line === '' || line[0] === ' ') return line;

  // Since a more-indented line adds a \n, breaks can't be followed by a space.
  var breakRe = / [^ ]/g; // note: the match index will always be <= length-2.
  var match;
  // start is an inclusive index. end, curr, and next are exclusive.
  var start = 0, end, curr = 0, next = 0;
  var result = '';

  // Invariants: 0 <= start <= length-1.
  //   0 <= curr <= next <= max(0, length-2). curr - start <= width.
  // Inside the loop:
  //   A match implies length >= 2, so curr and next are <= length-2.
  while ((match = breakRe.exec(line))) {
    next = match.index;
    // maintain invariant: curr - start <= width
    if (next - start > width) {
      end = (curr > start) ? curr : next; // derive end <= length-2
      result += '\n' + line.slice(start, end);
      // skip the space that was output as \n
      start = end + 1;                    // derive start <= length-1
    }
    curr = next;
  }

  // By the invariants, start <= length-1, so there is something left over.
  // It is either the whole string or a part starting from non-whitespace.
  result += '\n';
  // Insert a break if the remainder is too long and there is a break available.
  if (line.length - start > width && curr > start) {
    result += line.slice(start, curr) + '\n' + line.slice(curr + 1);
  } else {
    result += line.slice(start);
  }

  return result.slice(1); // drop extra \n joiner
}

// Escapes a double-quoted string.
function escapeString(string) {
  var result = '';
  var char = 0;
  var escapeSeq;

  for (var i = 0; i < string.length; char >= 0x10000 ? i += 2 : i++) {
    char = codePointAt(string, i);
    escapeSeq = ESCAPE_SEQUENCES[char];

    if (!escapeSeq && isPrintable(char)) {
      result += string[i];
      if (char >= 0x10000) result += string[i + 1];
    } else {
      result += escapeSeq || encodeHex(char);
    }
  }

  return result;
}

function writeFlowSequence(state, level, object) {
  var _result = '',
      _tag    = state.tag,
      index,
      length,
      value;

  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];

    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }

    // Write only valid elements, put null instead of invalid elements.
    if (writeNode(state, level, value, false, false) ||
        (typeof value === 'undefined' &&
         writeNode(state, level, null, false, false))) {

      if (_result !== '') _result += ',' + (!state.condenseFlow ? ' ' : '');
      _result += state.dump;
    }
  }

  state.tag = _tag;
  state.dump = '[' + _result + ']';
}

function writeBlockSequence(state, level, object, compact) {
  var _result = '',
      _tag    = state.tag,
      index,
      length,
      value;

  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];

    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }

    // Write only valid elements, put null instead of invalid elements.
    if (writeNode(state, level + 1, value, true, true, false, true) ||
        (typeof value === 'undefined' &&
         writeNode(state, level + 1, null, true, true, false, true))) {

      if (!compact || _result !== '') {
        _result += generateNextLine(state, level);
      }

      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        _result += '-';
      } else {
        _result += '- ';
      }

      _result += state.dump;
    }
  }

  state.tag = _tag;
  state.dump = _result || '[]'; // Empty sequence if no valid values.
}

function writeFlowMapping(state, level, object) {
  var _result       = '',
      _tag          = state.tag,
      objectKeyList = Object.keys(object),
      index,
      length,
      objectKey,
      objectValue,
      pairBuffer;

  for (index = 0, length = objectKeyList.length; index < length; index += 1) {

    pairBuffer = '';
    if (_result !== '') pairBuffer += ', ';

    if (state.condenseFlow) pairBuffer += '"';

    objectKey = objectKeyList[index];
    objectValue = object[objectKey];

    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }

    if (!writeNode(state, level, objectKey, false, false)) {
      continue; // Skip this pair because of invalid key;
    }

    if (state.dump.length > 1024) pairBuffer += '? ';

    pairBuffer += state.dump + (state.condenseFlow ? '"' : '') + ':' + (state.condenseFlow ? '' : ' ');

    if (!writeNode(state, level, objectValue, false, false)) {
      continue; // Skip this pair because of invalid value.
    }

    pairBuffer += state.dump;

    // Both key and value are valid.
    _result += pairBuffer;
  }

  state.tag = _tag;
  state.dump = '{' + _result + '}';
}

function writeBlockMapping(state, level, object, compact) {
  var _result       = '',
      _tag          = state.tag,
      objectKeyList = Object.keys(object),
      index,
      length,
      objectKey,
      objectValue,
      explicitPair,
      pairBuffer;

  // Allow sorting keys so that the output file is deterministic
  if (state.sortKeys === true) {
    // Default sorting
    objectKeyList.sort();
  } else if (typeof state.sortKeys === 'function') {
    // Custom sort function
    objectKeyList.sort(state.sortKeys);
  } else if (state.sortKeys) {
    // Something is wrong
    throw new exception('sortKeys must be a boolean or a function');
  }

  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = '';

    if (!compact || _result !== '') {
      pairBuffer += generateNextLine(state, level);
    }

    objectKey = objectKeyList[index];
    objectValue = object[objectKey];

    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }

    if (!writeNode(state, level + 1, objectKey, true, true, true)) {
      continue; // Skip this pair because of invalid key.
    }

    explicitPair = (state.tag !== null && state.tag !== '?') ||
                   (state.dump && state.dump.length > 1024);

    if (explicitPair) {
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        pairBuffer += '?';
      } else {
        pairBuffer += '? ';
      }
    }

    pairBuffer += state.dump;

    if (explicitPair) {
      pairBuffer += generateNextLine(state, level);
    }

    if (!writeNode(state, level + 1, objectValue, true, explicitPair)) {
      continue; // Skip this pair because of invalid value.
    }

    if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
      pairBuffer += ':';
    } else {
      pairBuffer += ': ';
    }

    pairBuffer += state.dump;

    // Both key and value are valid.
    _result += pairBuffer;
  }

  state.tag = _tag;
  state.dump = _result || '{}'; // Empty mapping if no valid pairs.
}

function detectType(state, object, explicit) {
  var _result, typeList, index, length, type, style;

  typeList = explicit ? state.explicitTypes : state.implicitTypes;

  for (index = 0, length = typeList.length; index < length; index += 1) {
    type = typeList[index];

    if ((type.instanceOf  || type.predicate) &&
        (!type.instanceOf || ((typeof object === 'object') && (object instanceof type.instanceOf))) &&
        (!type.predicate  || type.predicate(object))) {

      if (explicit) {
        if (type.multi && type.representName) {
          state.tag = type.representName(object);
        } else {
          state.tag = type.tag;
        }
      } else {
        state.tag = '?';
      }

      if (type.represent) {
        style = state.styleMap[type.tag] || type.defaultStyle;

        if (_toString.call(type.represent) === '[object Function]') {
          _result = type.represent(object, style);
        } else if (_hasOwnProperty.call(type.represent, style)) {
          _result = type.represent[style](object, style);
        } else {
          throw new exception('!<' + type.tag + '> tag resolver accepts not "' + style + '" style');
        }

        state.dump = _result;
      }

      return true;
    }
  }

  return false;
}

// Serializes `object` and writes it to global `result`.
// Returns true on success, or false on invalid object.
//
function writeNode(state, level, object, block, compact, iskey, isblockseq) {
  state.tag = null;
  state.dump = object;

  if (!detectType(state, object, false)) {
    detectType(state, object, true);
  }

  var type = _toString.call(state.dump);
  var inblock = block;
  var tagStr;

  if (block) {
    block = (state.flowLevel < 0 || state.flowLevel > level);
  }

  var objectOrArray = type === '[object Object]' || type === '[object Array]',
      duplicateIndex,
      duplicate;

  if (objectOrArray) {
    duplicateIndex = state.duplicates.indexOf(object);
    duplicate = duplicateIndex !== -1;
  }

  if ((state.tag !== null && state.tag !== '?') || duplicate || (state.indent !== 2 && level > 0)) {
    compact = false;
  }

  if (duplicate && state.usedDuplicates[duplicateIndex]) {
    state.dump = '*ref_' + duplicateIndex;
  } else {
    if (objectOrArray && duplicate && !state.usedDuplicates[duplicateIndex]) {
      state.usedDuplicates[duplicateIndex] = true;
    }
    if (type === '[object Object]') {
      if (block && (Object.keys(state.dump).length !== 0)) {
        writeBlockMapping(state, level, state.dump, compact);
        if (duplicate) {
          state.dump = '&ref_' + duplicateIndex + state.dump;
        }
      } else {
        writeFlowMapping(state, level, state.dump);
        if (duplicate) {
          state.dump = '&ref_' + duplicateIndex + ' ' + state.dump;
        }
      }
    } else if (type === '[object Array]') {
      if (block && (state.dump.length !== 0)) {
        if (state.noArrayIndent && !isblockseq && level > 0) {
          writeBlockSequence(state, level - 1, state.dump, compact);
        } else {
          writeBlockSequence(state, level, state.dump, compact);
        }
        if (duplicate) {
          state.dump = '&ref_' + duplicateIndex + state.dump;
        }
      } else {
        writeFlowSequence(state, level, state.dump);
        if (duplicate) {
          state.dump = '&ref_' + duplicateIndex + ' ' + state.dump;
        }
      }
    } else if (type === '[object String]') {
      if (state.tag !== '?') {
        writeScalar(state, state.dump, level, iskey, inblock);
      }
    } else if (type === '[object Undefined]') {
      return false;
    } else {
      if (state.skipInvalid) return false;
      throw new exception('unacceptable kind of an object to dump ' + type);
    }

    if (state.tag !== null && state.tag !== '?') {
      // Need to encode all characters except those allowed by the spec:
      //
      // [35] ns-dec-digit    ::=  [#x30-#x39] /* 0-9 */
      // [36] ns-hex-digit    ::=  ns-dec-digit
      //                         | [#x41-#x46] /* A-F */ | [#x61-#x66] /* a-f */
      // [37] ns-ascii-letter ::=  [#x41-#x5A] /* A-Z */ | [#x61-#x7A] /* a-z */
      // [38] ns-word-char    ::=  ns-dec-digit | ns-ascii-letter | “-”
      // [39] ns-uri-char     ::=  “%” ns-hex-digit ns-hex-digit | ns-word-char | “#”
      //                         | “;” | “/” | “?” | “:” | “@” | “&” | “=” | “+” | “$” | “,”
      //                         | “_” | “.” | “!” | “~” | “*” | “'” | “(” | “)” | “[” | “]”
      //
      // Also need to encode '!' because it has special meaning (end of tag prefix).
      //
      tagStr = encodeURI(
        state.tag[0] === '!' ? state.tag.slice(1) : state.tag
      ).replace(/!/g, '%21');

      if (state.tag[0] === '!') {
        tagStr = '!' + tagStr;
      } else if (tagStr.slice(0, 18) === 'tag:yaml.org,2002:') {
        tagStr = '!!' + tagStr.slice(18);
      } else {
        tagStr = '!<' + tagStr + '>';
      }

      state.dump = tagStr + ' ' + state.dump;
    }
  }

  return true;
}

function getDuplicateReferences(object, state) {
  var objects = [],
      duplicatesIndexes = [],
      index,
      length;

  inspectNode(object, objects, duplicatesIndexes);

  for (index = 0, length = duplicatesIndexes.length; index < length; index += 1) {
    state.duplicates.push(objects[duplicatesIndexes[index]]);
  }
  state.usedDuplicates = new Array(length);
}

function inspectNode(object, objects, duplicatesIndexes) {
  var objectKeyList,
      index,
      length;

  if (object !== null && typeof object === 'object') {
    index = objects.indexOf(object);
    if (index !== -1) {
      if (duplicatesIndexes.indexOf(index) === -1) {
        duplicatesIndexes.push(index);
      }
    } else {
      objects.push(object);

      if (Array.isArray(object)) {
        for (index = 0, length = object.length; index < length; index += 1) {
          inspectNode(object[index], objects, duplicatesIndexes);
        }
      } else {
        objectKeyList = Object.keys(object);

        for (index = 0, length = objectKeyList.length; index < length; index += 1) {
          inspectNode(object[objectKeyList[index]], objects, duplicatesIndexes);
        }
      }
    }
  }
}

function dump$1(input, options) {
  options = options || {};

  var state = new State(options);

  if (!state.noRefs) getDuplicateReferences(input, state);

  var value = input;

  if (state.replacer) {
    value = state.replacer.call({ '': value }, '', value);
  }

  if (writeNode(state, 0, value, true, true)) return state.dump + '\n';

  return '';
}

var dump_1 = dump$1;

var dumper = {
	dump: dump_1
};

function renamed(from, to) {
  return function () {
    throw new Error('Function yaml.' + from + ' is removed in js-yaml 4. ' +
      'Use yaml.' + to + ' instead, which is now safe by default.');
  };
}


var Type                = type;
var Schema              = schema;
var FAILSAFE_SCHEMA     = failsafe;
var JSON_SCHEMA         = json;
var CORE_SCHEMA         = core;
var DEFAULT_SCHEMA      = _default;
var load                = loader.load;
var loadAll             = loader.loadAll;
var dump                = dumper.dump;
var YAMLException       = exception;

// Re-export all types in case user wants to create custom schema
var types = {
  binary:    binary,
  float:     float,
  map:       map,
  null:      _null,
  pairs:     pairs,
  set:       set,
  timestamp: timestamp,
  bool:      bool,
  int:       int,
  merge:     merge,
  omap:      omap,
  seq:       seq,
  str:       str
};

// Removed functions from JS-YAML 3.0.x
var safeLoad            = renamed('safeLoad', 'load');
var safeLoadAll         = renamed('safeLoadAll', 'loadAll');
var safeDump            = renamed('safeDump', 'dump');

var jsYaml = {
	Type: Type,
	Schema: Schema,
	FAILSAFE_SCHEMA: FAILSAFE_SCHEMA,
	JSON_SCHEMA: JSON_SCHEMA,
	CORE_SCHEMA: CORE_SCHEMA,
	DEFAULT_SCHEMA: DEFAULT_SCHEMA,
	load: load,
	loadAll: loadAll,
	dump: dump,
	YAMLException: YAMLException,
	types: types,
	safeLoad: safeLoad,
	safeLoadAll: safeLoadAll,
	safeDump: safeDump
};

const {toDisplayString:_toDisplayString$2,createTextVNode:_createTextVNode$2,resolveComponent:_resolveComponent$2,withCtx:_withCtx$2,createVNode:_createVNode$2,openBlock:_openBlock$2,createBlock:_createBlock$2,createCommentVNode:_createCommentVNode$2,createElementBlock:_createElementBlock$1,withModifiers:_withModifiers$2,createElementVNode:_createElementVNode$1} = await importShared('vue');


const _hoisted_1$1 = { key: 0 };
const _hoisted_2$1 = {
  key: 0,
  class: "mt-2"
};
const _hoisted_3$1 = {
  key: 0,
  class: "mt-2"
};
const _hoisted_4$1 = {
  key: 0,
  class: "mt-2"
};
const _hoisted_5$1 = {
  key: 0,
  class: "mt-2"
};
const _hoisted_6$1 = {
  key: 0,
  class: "mt-2"
};
const _hoisted_7$1 = { key: 0 };

const {ref: ref$2,watch,computed: computed$2} = await importShared('vue');



const _sfc_main$2 = {
  __name: 'ProxiesDialog',
  props: {
  modelValue: {type: Boolean, default: false},
  proxyData: {type: Object, default: null},
  loading: {type: Boolean, default: false}
},
  emits: ['update:modelValue', 'save'],
  setup(__props, { emit: __emit }) {

const props = __props;

const emit = __emit;

const dialog = computed$2({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value)
});

const isEditing = computed$2(() => !!props.proxyData?.name);

const proxyForm = ref$2(null);
const tab = ref$2('general');
const proxy = ref$2({});
const wsHeaderString = ref$2('');
const httpHeaderString = ref$2('');

const jsonValidator = (value) => {
  if (!value) return true
  try {
    JSON.parse(value);
    return true
  } catch (e) {
    return '无效的JSON格式'
  }
};

const proxyTypes = ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'http', 'snell', 'tuic', 'hysteria', 'hysteria2'];

// Default structure to avoid template errors
const getDefaultProxy = () => ({
  name: '',
  type: 'ss',
  server: '',
  port: 443,
  udp: false,
  tfo: false,
  mptcp: false,
  tls: false,
  'skip-cert-verify': false,
  alpn: [],
  network: null,
  'ws-opts': {
    path: '/',
    headers: {},
    'max-early-data': null,
    'early-data-header-name': null,
    'v2ray-http-upgrade': false,
    'v2ray-http-upgrade-fast-open': false
  },
  'http-opts': {method: 'GET', path: ['/'], headers: {}},
  'h2-opts': {host: [], path: '/'},
  'grpc-opts': {'grpc-service-name': ''},
  smux: {
    enabled: false,
    protocol: 'h2mux',
    'max-connections': null,
    'min-streams': null,
    'max-streams': null,
    padding: false,
    statistic: false,
    'only-tcp': false,
    'brutal-opts': {
      enabled: false,
      up: null,
      down: null
    }
  },
  rescind: false,
});

// Watch for props changes to initialize data when the dialog opens
watch(() => props.modelValue, (newValue) => {
  // Guard to run only when the dialog opens
  if (newValue) {
    // Deep copy proxyData or use default.
    const defaultProxy = getDefaultProxy();
    proxy.value = JSON.parse(JSON.stringify(props.proxyData || defaultProxy));

    // Ensure network field exists to prevent undefined model value
    if (!('network' in proxy.value)) {
      proxy.value.network = null;
    }

    // Ensure nested opts objects exist to prevent template errors
    proxy.value['ws-opts'] = Object.assign({}, defaultProxy['ws-opts'], proxy.value['ws-opts']);
    proxy.value['http-opts'] = Object.assign({}, defaultProxy['http-opts'], proxy.value['http-opts']);
    proxy.value['h2-opts'] = Object.assign({}, defaultProxy['h2-opts'], proxy.value['h2-opts']);
    proxy.value['grpc-opts'] = Object.assign({}, defaultProxy['grpc-opts'], proxy.value['grpc-opts']);
    proxy.value.smux = Object.assign({}, defaultProxy.smux, proxy.value.smux);
    proxy.value.smux['brutal-opts'] = Object.assign({}, defaultProxy.smux['brutal-opts'], proxy.value.smux['brutal-opts']);

    // Convert headers object to JSON string for ws-opts for easier editing
    if (proxy.value['ws-opts']?.headers) {
      try {
        wsHeaderString.value = JSON.stringify(proxy.value['ws-opts'].headers, null, 2);
      } catch (e) {
        wsHeaderString.value = '{}';
      }
    } else {
      wsHeaderString.value = '{}';
    }

    // Convert headers object to JSON string for http-opts for easier editing
    if (proxy.value['http-opts']?.headers) {
      try {
        httpHeaderString.value = JSON.stringify(proxy.value['http-opts'].headers, null, 2);
      } catch (e) {
        httpHeaderString.value = '{}';
      }
    } else {
      httpHeaderString.value = '{}';
    }
  }
}, {immediate: true});

// Parse header strings back to objects before saving
const parseHeaders = () => {
  if (proxy.value.network === 'ws') {
    try {
      proxy.value['ws-opts'].headers = JSON.parse(wsHeaderString.value || '{}');
    } catch (e) {
      console.error("Invalid JSON format for ws headers:", e);
      proxy.value['ws-opts'].headers = {};
    }
  }
  if (proxy.value.network === 'http') {
    try {
      proxy.value['http-opts'].headers = JSON.parse(httpHeaderString.value || '{}');
    } catch (e) {
      console.error("Invalid JSON format for http headers:", e);
      proxy.value['http-opts'].headers = {};
    }
  }
};

const handleSave = async () => {
  const {valid} = await proxyForm.value.validate();
  if (valid) {
    parseHeaders();

    // Create a clean proxy object to emit
    const finalProxy = {...proxy.value};

    // Clean up unused transport options
    if (finalProxy.network !== 'ws') delete finalProxy['ws-opts'];
    if (finalProxy.network !== 'http') delete finalProxy['http-opts'];
    if (finalProxy.network !== 'h2') delete finalProxy['h2-opts'];
    if (finalProxy.network !== 'grpc') delete finalProxy['grpc-opts'];

    // Clean up smux if disabled
    if (!finalProxy.smux?.enabled) {
      delete finalProxy.smux;
    } else if (!finalProxy.smux['brutal-opts']?.enabled) {
      delete finalProxy.smux['brutal-opts'];
    }

    // Clean up unused TLS options
    if (!finalProxy.tls) {
      delete finalProxy.servername;
      delete finalProxy.fingerprint;
      delete finalProxy.alpn;
      delete finalProxy['skip-cert-verify'];
      delete finalProxy['client-fingerprint'];
      delete finalProxy.sni;
    } else {
      // If TLS is enabled, clean up the one that is not used
      if (['vmess', 'vless'].includes(finalProxy.type)) {
        delete finalProxy.sni;
      } else {
        delete finalProxy.servername;
      }
      if (!['vmess', 'vless', 'trojan'].includes(finalProxy.type)) {
        delete finalProxy['client-fingerprint'];
      }
    }
    emit('save', finalProxy);
  }
};

const handleCancel = () => {
  dialog.value = false;
};

return (_ctx, _cache) => {
  const _component_v_card_title = _resolveComponent$2("v-card-title");
  const _component_v_tab = _resolveComponent$2("v-tab");
  const _component_v_tabs = _resolveComponent$2("v-tabs");
  const _component_v_text_field = _resolveComponent$2("v-text-field");
  const _component_v_col = _resolveComponent$2("v-col");
  const _component_v_select = _resolveComponent$2("v-select");
  const _component_v_switch = _resolveComponent$2("v-switch");
  const _component_v_row = _resolveComponent$2("v-row");
  const _component_v_container = _resolveComponent$2("v-container");
  const _component_v_window_item = _resolveComponent$2("v-window-item");
  const _component_v_combobox = _resolveComponent$2("v-combobox");
  const _component_v_expand_transition = _resolveComponent$2("v-expand-transition");
  const _component_v_textarea = _resolveComponent$2("v-textarea");
  const _component_v_card_text = _resolveComponent$2("v-card-text");
  const _component_v_card = _resolveComponent$2("v-card");
  const _component_v_window = _resolveComponent$2("v-window");
  const _component_v_form = _resolveComponent$2("v-form");
  const _component_v_alert = _resolveComponent$2("v-alert");
  const _component_v_checkbox = _resolveComponent$2("v-checkbox");
  const _component_v_spacer = _resolveComponent$2("v-spacer");
  const _component_v_btn = _resolveComponent$2("v-btn");
  const _component_v_card_actions = _resolveComponent$2("v-card-actions");
  const _component_v_dialog = _resolveComponent$2("v-dialog");

  return (_openBlock$2(), _createBlock$2(_component_v_dialog, {
    modelValue: dialog.value,
    "onUpdate:modelValue": _cache[45] || (_cache[45] = $event => ((dialog).value = $event)),
    "max-width": "50rem",
    persistent: ""
  }, {
    default: _withCtx$2(() => [
      _createVNode$2(_component_v_card, null, {
        default: _withCtx$2(() => [
          _createVNode$2(_component_v_card_title, null, {
            default: _withCtx$2(() => [
              _createTextVNode$2(_toDisplayString$2(isEditing.value ? '覆写代理' : '添加代理'), 1)
            ]),
            _: 1
          }),
          _createVNode$2(_component_v_card_text, { class: "pa-2" }, {
            default: _withCtx$2(() => [
              _createVNode$2(_component_v_form, {
                ref_key: "proxyForm",
                ref: proxyForm,
                onSubmit: _withModifiers$2(handleSave, ["prevent"])
              }, {
                default: _withCtx$2(() => [
                  _createVNode$2(_component_v_tabs, {
                    modelValue: tab.value,
                    "onUpdate:modelValue": _cache[0] || (_cache[0] = $event => ((tab).value = $event)),
                    "background-color": "primary",
                    dark: "",
                    grow: ""
                  }, {
                    default: _withCtx$2(() => [
                      _createVNode$2(_component_v_tab, { value: "general" }, {
                        default: _withCtx$2(() => _cache[46] || (_cache[46] = [
                          _createTextVNode$2("通用")
                        ])),
                        _: 1
                      }),
                      _createVNode$2(_component_v_tab, { value: "tls" }, {
                        default: _withCtx$2(() => _cache[47] || (_cache[47] = [
                          _createTextVNode$2("TLS")
                        ])),
                        _: 1
                      }),
                      _createVNode$2(_component_v_tab, { value: "transport" }, {
                        default: _withCtx$2(() => _cache[48] || (_cache[48] = [
                          _createTextVNode$2("传输层")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"]),
                  _createVNode$2(_component_v_window, {
                    modelValue: tab.value,
                    "onUpdate:modelValue": _cache[43] || (_cache[43] = $event => ((tab).value = $event)),
                    class: "pt-4"
                  }, {
                    default: _withCtx$2(() => [
                      _createVNode$2(_component_v_window_item, { value: "general" }, {
                        default: _withCtx$2(() => [
                          _createVNode$2(_component_v_container, { fluid: "" }, {
                            default: _withCtx$2(() => [
                              _createVNode$2(_component_v_row, { dense: "" }, {
                                default: _withCtx$2(() => [
                                  _createVNode$2(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_text_field, {
                                        modelValue: proxy.value.name,
                                        "onUpdate:modelValue": _cache[1] || (_cache[1] = $event => ((proxy.value.name) = $event)),
                                        disabled: "",
                                        label: "名称 (name)",
                                        rules: [v => !!v || '名称不能为空'],
                                        hint: "代理名称",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue", "rules"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_select, {
                                        modelValue: proxy.value.type,
                                        "onUpdate:modelValue": _cache[2] || (_cache[2] = $event => ((proxy.value.type) = $event)),
                                        label: "类型 (type)",
                                        items: proxyTypes,
                                        rules: [v => !!v || '类型不能为空'],
                                        hint: "代理协议类型",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue", "rules"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_text_field, {
                                        modelValue: proxy.value.server,
                                        "onUpdate:modelValue": _cache[3] || (_cache[3] = $event => ((proxy.value.server) = $event)),
                                        label: "服务器 (server)",
                                        rules: [v => !!v || '服务器地址不能为空'],
                                        hint: "代理服务器地址 (域名/IP)",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue", "rules"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_text_field, {
                                        modelValue: proxy.value.port,
                                        "onUpdate:modelValue": _cache[4] || (_cache[4] = $event => ((proxy.value.port) = $event)),
                                        modelModifiers: { number: true },
                                        label: "端口 (port)",
                                        type: "number",
                                        rules: [v => !!v || '端口不能为空'],
                                        hint: "代理服务器端口",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue", "rules"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_select, {
                                        modelValue: proxy.value['ip-version'],
                                        "onUpdate:modelValue": _cache[5] || (_cache[5] = $event => ((proxy.value['ip-version']) = $event)),
                                        label: "IP版本 (ip-version)",
                                        items: ['dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer'],
                                        hint: "出站使用的IP版本",
                                        clearable: "",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_text_field, {
                                        modelValue: proxy.value['interface-name'],
                                        "onUpdate:modelValue": _cache[6] || (_cache[6] = $event => ((proxy.value['interface-name']) = $event)),
                                        label: "网络接口 (interface-name)",
                                        hint: "指定出站网络接口",
                                        clearable: "",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_text_field, {
                                        modelValue: proxy.value['routing-mark'],
                                        "onUpdate:modelValue": _cache[7] || (_cache[7] = $event => ((proxy.value['routing-mark']) = $event)),
                                        modelModifiers: { number: true },
                                        label: "路由标记 (routing-mark)",
                                        type: "number",
                                        hint: "为出站连接设置路由标记",
                                        clearable: "",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_text_field, {
                                        modelValue: proxy.value['dialer-proxy'],
                                        "onUpdate:modelValue": _cache[8] || (_cache[8] = $event => ((proxy.value['dialer-proxy']) = $event)),
                                        label: "拨号代理 (dialer-proxy)",
                                        hint: "指定当前代理通过哪个代理建立连接",
                                        clearable: "",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "4",
                                    sm: "4"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_switch, {
                                        modelValue: proxy.value.udp,
                                        "onUpdate:modelValue": _cache[9] || (_cache[9] = $event => ((proxy.value.udp) = $event)),
                                        label: "UDP",
                                        hint: "是否允许UDP",
                                        inset: "",
                                        color: "primary"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "4",
                                    sm: "4"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_switch, {
                                        modelValue: proxy.value.tfo,
                                        "onUpdate:modelValue": _cache[10] || (_cache[10] = $event => ((proxy.value.tfo) = $event)),
                                        label: "TFO",
                                        hint: "启用 TCP Fast Open",
                                        inset: "",
                                        color: "primary"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode$2(_component_v_col, {
                                    cols: "4",
                                    sm: "4"
                                  }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_switch, {
                                        modelValue: proxy.value.mptcp,
                                        "onUpdate:modelValue": _cache[11] || (_cache[11] = $event => ((proxy.value.mptcp) = $event)),
                                        label: "MPTCP",
                                        hint: "启用 Multi-Path TCP",
                                        inset: "",
                                        color: "primary"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode$2(_component_v_window_item, { value: "tls" }, {
                        default: _withCtx$2(() => [
                          _createVNode$2(_component_v_container, { fluid: "" }, {
                            default: _withCtx$2(() => [
                              _createVNode$2(_component_v_row, { dense: "" }, {
                                default: _withCtx$2(() => [
                                  _createVNode$2(_component_v_col, { cols: "12" }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_switch, {
                                        modelValue: proxy.value.tls,
                                        "onUpdate:modelValue": _cache[12] || (_cache[12] = $event => ((proxy.value.tls) = $event)),
                                        label: "启用 TLS",
                                        inset: "",
                                        color: "primary"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              }),
                              _createVNode$2(_component_v_expand_transition, null, {
                                default: _withCtx$2(() => [
                                  (proxy.value.tls)
                                    ? (_openBlock$2(), _createElementBlock$1("div", _hoisted_1$1, [
                                        _createVNode$2(_component_v_row, { dense: "" }, {
                                          default: _withCtx$2(() => [
                                            _createVNode$2(_component_v_col, {
                                              cols: "12",
                                              md: "6"
                                            }, {
                                              default: _withCtx$2(() => [
                                                (['vmess', 'vless'].includes(proxy.value.type))
                                                  ? (_openBlock$2(), _createBlock$2(_component_v_text_field, {
                                                      key: 0,
                                                      modelValue: proxy.value.servername,
                                                      "onUpdate:modelValue": _cache[13] || (_cache[13] = $event => ((proxy.value.servername) = $event)),
                                                      label: "服务器名称 (servername)",
                                                      hint: "TLS服务器名称(SNI)",
                                                      clearable: "",
                                                      "persistent-hint": "",
                                                      variant: "outlined"
                                                    }, null, 8, ["modelValue"]))
                                                  : (_openBlock$2(), _createBlock$2(_component_v_text_field, {
                                                      key: 1,
                                                      modelValue: proxy.value.sni,
                                                      "onUpdate:modelValue": _cache[14] || (_cache[14] = $event => ((proxy.value.sni) = $event)),
                                                      label: "SNI",
                                                      hint: "TLS服务器名称(SNI)",
                                                      clearable: "",
                                                      "persistent-hint": "",
                                                      variant: "outlined"
                                                    }, null, 8, ["modelValue"]))
                                              ]),
                                              _: 1
                                            }),
                                            _createVNode$2(_component_v_col, {
                                              cols: "12",
                                              md: "6"
                                            }, {
                                              default: _withCtx$2(() => [
                                                _createVNode$2(_component_v_text_field, {
                                                  modelValue: proxy.value.fingerprint,
                                                  "onUpdate:modelValue": _cache[15] || (_cache[15] = $event => ((proxy.value.fingerprint) = $event)),
                                                  label: "指纹 (fingerprint)",
                                                  hint: "证书指纹",
                                                  clearable: "",
                                                  "persistent-hint": "",
                                                  variant: "outlined"
                                                }, null, 8, ["modelValue"])
                                              ]),
                                              _: 1
                                            }),
                                            _createVNode$2(_component_v_col, { cols: "12" }, {
                                              default: _withCtx$2(() => [
                                                _createVNode$2(_component_v_combobox, {
                                                  modelValue: proxy.value.alpn,
                                                  "onUpdate:modelValue": _cache[16] || (_cache[16] = $event => ((proxy.value.alpn) = $event)),
                                                  label: "ALPN",
                                                  hint: "应用层协议协商",
                                                  multiple: "",
                                                  chips: "",
                                                  clearable: "",
                                                  "deletable-chips": "",
                                                  "persistent-hint": "",
                                                  variant: "outlined"
                                                }, null, 8, ["modelValue"])
                                              ]),
                                              _: 1
                                            }),
                                            (['vmess', 'vless', 'trojan'].includes(proxy.value.type))
                                              ? (_openBlock$2(), _createBlock$2(_component_v_col, {
                                                  key: 0,
                                                  cols: "12",
                                                  md: "6"
                                                }, {
                                                  default: _withCtx$2(() => [
                                                    _createVNode$2(_component_v_select, {
                                                      modelValue: proxy.value['client-fingerprint'],
                                                      "onUpdate:modelValue": _cache[17] || (_cache[17] = $event => ((proxy.value['client-fingerprint']) = $event)),
                                                      label: "客户端指纹 (client-fingerprint)",
                                                      items: ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random'],
                                                      hint: "uTLS客户端指紋",
                                                      clearable: "",
                                                      "persistent-hint": "",
                                                      variant: "outlined"
                                                    }, null, 8, ["modelValue"])
                                                  ]),
                                                  _: 1
                                                }))
                                              : _createCommentVNode$2("", true),
                                            _createVNode$2(_component_v_col, {
                                              cols: "12",
                                              md: "6",
                                              class: "d-flex align-center"
                                            }, {
                                              default: _withCtx$2(() => [
                                                _createVNode$2(_component_v_switch, {
                                                  modelValue: proxy.value['skip-cert-verify'],
                                                  "onUpdate:modelValue": _cache[18] || (_cache[18] = $event => ((proxy.value['skip-cert-verify']) = $event)),
                                                  label: "跳过证书验证",
                                                  inset: "",
                                                  "persistent-hint": "",
                                                  color: "primary"
                                                }, null, 8, ["modelValue"])
                                              ]),
                                              _: 1
                                            })
                                          ]),
                                          _: 1
                                        })
                                      ]))
                                    : _createCommentVNode$2("", true)
                                ]),
                                _: 1
                              })
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode$2(_component_v_window_item, { value: "transport" }, {
                        default: _withCtx$2(() => [
                          _createVNode$2(_component_v_container, { fluid: "" }, {
                            default: _withCtx$2(() => [
                              _createVNode$2(_component_v_row, null, {
                                default: _withCtx$2(() => [
                                  _createVNode$2(_component_v_col, { cols: "12" }, {
                                    default: _withCtx$2(() => [
                                      _createVNode$2(_component_v_select, {
                                        modelValue: proxy.value.network,
                                        "onUpdate:modelValue": _cache[19] || (_cache[19] = $event => ((proxy.value.network) = $event)),
                                        label: "网络 (network)",
                                        items: ['http', 'h2', 'grpc', 'ws'],
                                        hint: "传输层协议",
                                        clearable: "",
                                        "persistent-hint": "",
                                        variant: "outlined"
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              }),
                              _createVNode$2(_component_v_expand_transition, null, {
                                default: _withCtx$2(() => [
                                  (proxy.value.network === 'ws')
                                    ? (_openBlock$2(), _createElementBlock$1("div", _hoisted_2$1, [
                                        _createVNode$2(_component_v_card, { variant: "tonal" }, {
                                          default: _withCtx$2(() => [
                                            _createVNode$2(_component_v_card_title, { class: "text-subtitle-1 py-2" }, {
                                              default: _withCtx$2(() => _cache[49] || (_cache[49] = [
                                                _createTextVNode$2("WebSocket 选项")
                                              ])),
                                              _: 1
                                            }),
                                            _createVNode$2(_component_v_card_text, null, {
                                              default: _withCtx$2(() => [
                                                _createVNode$2(_component_v_row, null, {
                                                  default: _withCtx$2(() => [
                                                    _createVNode$2(_component_v_col, {
                                                      cols: "12",
                                                      md: "6"
                                                    }, {
                                                      default: _withCtx$2(() => [
                                                        _createVNode$2(_component_v_switch, {
                                                          modelValue: proxy.value['ws-opts']['v2ray-http-upgrade'],
                                                          "onUpdate:modelValue": _cache[20] || (_cache[20] = $event => ((proxy.value['ws-opts']['v2ray-http-upgrade']) = $event)),
                                                          label: "v2ray-http-upgrade",
                                                          hint: "启用 http upgrade",
                                                          inset: "",
                                                          color: "primary"
                                                        }, null, 8, ["modelValue"])
                                                      ]),
                                                      _: 1
                                                    }),
                                                    _createVNode$2(_component_v_col, {
                                                      cols: "12",
                                                      md: "6"
                                                    }, {
                                                      default: _withCtx$2(() => [
                                                        _createVNode$2(_component_v_switch, {
                                                          modelValue: proxy.value['ws-opts']['v2ray-http-upgrade-fast-open'],
                                                          "onUpdate:modelValue": _cache[21] || (_cache[21] = $event => ((proxy.value['ws-opts']['v2ray-http-upgrade-fast-open']) = $event)),
                                                          label: "v2ray-http-upgrade-fast-open",
                                                          hint: "启用 http upgrade 的 fast open",
                                                          inset: "",
                                                          color: "primary"
                                                        }, null, 8, ["modelValue"])
                                                      ]),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 1
                                                }),
                                                _createVNode$2(_component_v_text_field, {
                                                  modelValue: proxy.value['ws-opts'].path,
                                                  "onUpdate:modelValue": _cache[22] || (_cache[22] = $event => ((proxy.value['ws-opts'].path) = $event)),
                                                  label: "路径 (path)",
                                                  hint: "WebSocket请求路径",
                                                  variant: "outlined",
                                                  class: "mb-2"
                                                }, null, 8, ["modelValue"]),
                                                _createVNode$2(_component_v_text_field, {
                                                  modelValue: proxy.value['ws-opts']['max-early-data'],
                                                  "onUpdate:modelValue": _cache[23] || (_cache[23] = $event => ((proxy.value['ws-opts']['max-early-data']) = $event)),
                                                  modelModifiers: { number: true },
                                                  label: "max-early-data",
                                                  type: "number",
                                                  hint: "Early Data 首包长度阈值",
                                                  variant: "outlined",
                                                  class: "mb-2",
                                                  clearable: ""
                                                }, null, 8, ["modelValue"]),
                                                _createVNode$2(_component_v_text_field, {
                                                  modelValue: proxy.value['ws-opts']['early-data-header-name'],
                                                  "onUpdate:modelValue": _cache[24] || (_cache[24] = $event => ((proxy.value['ws-opts']['early-data-header-name']) = $event)),
                                                  label: "early-data-header-name",
                                                  variant: "outlined",
                                                  class: "mb-2",
                                                  clearable: ""
                                                }, null, 8, ["modelValue"]),
                                                _createVNode$2(_component_v_textarea, {
                                                  modelValue: wsHeaderString.value,
                                                  "onUpdate:modelValue": _cache[25] || (_cache[25] = $event => ((wsHeaderString).value = $event)),
                                                  label: "请求头 (headers)",
                                                  hint: "请输入JSON格式字符串, 例如: {\"Host\":\"example.com\"}",
                                                  variant: "outlined",
                                                  rows: "3",
                                                  rules: [jsonValidator]
                                                }, null, 8, ["modelValue", "rules"])
                                              ]),
                                              _: 1
                                            })
                                          ]),
                                          _: 1
                                        })
                                      ]))
                                    : _createCommentVNode$2("", true)
                                ]),
                                _: 1
                              }),
                              _createVNode$2(_component_v_expand_transition, null, {
                                default: _withCtx$2(() => [
                                  (proxy.value.network === 'http')
                                    ? (_openBlock$2(), _createElementBlock$1("div", _hoisted_3$1, [
                                        _createVNode$2(_component_v_card, { variant: "tonal" }, {
                                          default: _withCtx$2(() => [
                                            _createVNode$2(_component_v_card_title, { class: "text-subtitle-1 py-2" }, {
                                              default: _withCtx$2(() => _cache[50] || (_cache[50] = [
                                                _createTextVNode$2("HTTP 选项")
                                              ])),
                                              _: 1
                                            }),
                                            _createVNode$2(_component_v_card_text, null, {
                                              default: _withCtx$2(() => [
                                                _createVNode$2(_component_v_text_field, {
                                                  modelValue: proxy.value['http-opts'].method,
                                                  "onUpdate:modelValue": _cache[26] || (_cache[26] = $event => ((proxy.value['http-opts'].method) = $event)),
                                                  label: "方法 (method)",
                                                  hint: "HTTP请求方法",
                                                  variant: "outlined",
                                                  class: "mb-2"
                                                }, null, 8, ["modelValue"]),
                                                _createVNode$2(_component_v_combobox, {
                                                  modelValue: proxy.value['http-opts'].path,
                                                  "onUpdate:modelValue": _cache[27] || (_cache[27] = $event => ((proxy.value['http-opts'].path) = $event)),
                                                  label: "路径 (path)",
                                                  hint: "HTTP请求路径",
                                                  multiple: "",
                                                  chips: "",
                                                  clearable: "",
                                                  "deletable-chips": "",
                                                  variant: "outlined",
                                                  class: "mb-2"
                                                }, null, 8, ["modelValue"]),
                                                _createVNode$2(_component_v_textarea, {
                                                  modelValue: httpHeaderString.value,
                                                  "onUpdate:modelValue": _cache[28] || (_cache[28] = $event => ((httpHeaderString).value = $event)),
                                                  label: "请求头 (headers)",
                                                  hint: "请输入JSON格式字符串, 例如: {\"Host\":\"example.com\"}",
                                                  variant: "outlined",
                                                  rows: "3",
                                                  rules: [jsonValidator]
                                                }, null, 8, ["modelValue", "rules"])
                                              ]),
                                              _: 1
                                            })
                                          ]),
                                          _: 1
                                        })
                                      ]))
                                    : _createCommentVNode$2("", true)
                                ]),
                                _: 1
                              }),
                              _createVNode$2(_component_v_expand_transition, null, {
                                default: _withCtx$2(() => [
                                  (proxy.value.network === 'h2')
                                    ? (_openBlock$2(), _createElementBlock$1("div", _hoisted_4$1, [
                                        _createVNode$2(_component_v_card, { variant: "tonal" }, {
                                          default: _withCtx$2(() => [
                                            _createVNode$2(_component_v_card_title, { class: "text-subtitle-1 py-2" }, {
                                              default: _withCtx$2(() => _cache[51] || (_cache[51] = [
                                                _createTextVNode$2("H2 选项")
                                              ])),
                                              _: 1
                                            }),
                                            _createVNode$2(_component_v_card_text, null, {
                                              default: _withCtx$2(() => [
                                                _createVNode$2(_component_v_text_field, {
                                                  modelValue: proxy.value['h2-opts'].path,
                                                  "onUpdate:modelValue": _cache[29] || (_cache[29] = $event => ((proxy.value['h2-opts'].path) = $event)),
                                                  label: "路径 (path)",
                                                  hint: "H2请求路径",
                                                  variant: "outlined",
                                                  class: "mb-2"
                                                }, null, 8, ["modelValue"]),
                                                _createVNode$2(_component_v_combobox, {
                                                  modelValue: proxy.value['h2-opts'].host,
                                                  "onUpdate:modelValue": _cache[30] || (_cache[30] = $event => ((proxy.value['h2-opts'].host) = $event)),
                                                  label: "主机 (host)",
                                                  hint: "主机域名列表",
                                                  multiple: "",
                                                  chips: "",
                                                  clearable: "",
                                                  "deletable-chips": "",
                                                  variant: "outlined"
                                                }, null, 8, ["modelValue"])
                                              ]),
                                              _: 1
                                            })
                                          ]),
                                          _: 1
                                        })
                                      ]))
                                    : _createCommentVNode$2("", true)
                                ]),
                                _: 1
                              }),
                              _createVNode$2(_component_v_expand_transition, null, {
                                default: _withCtx$2(() => [
                                  (proxy.value.network === 'grpc')
                                    ? (_openBlock$2(), _createElementBlock$1("div", _hoisted_5$1, [
                                        _createVNode$2(_component_v_card, { variant: "tonal" }, {
                                          default: _withCtx$2(() => [
                                            _createVNode$2(_component_v_card_title, { class: "text-subtitle-1 py-2" }, {
                                              default: _withCtx$2(() => _cache[52] || (_cache[52] = [
                                                _createTextVNode$2("gRPC 选项")
                                              ])),
                                              _: 1
                                            }),
                                            _createVNode$2(_component_v_card_text, null, {
                                              default: _withCtx$2(() => [
                                                _createVNode$2(_component_v_text_field, {
                                                  modelValue: proxy.value['grpc-opts']['grpc-service-name'],
                                                  "onUpdate:modelValue": _cache[31] || (_cache[31] = $event => ((proxy.value['grpc-opts']['grpc-service-name']) = $event)),
                                                  label: "服务名称 (grpc-service-name)",
                                                  hint: "gRPC服务名称",
                                                  variant: "outlined"
                                                }, null, 8, ["modelValue"])
                                              ]),
                                              _: 1
                                            })
                                          ]),
                                          _: 1
                                        })
                                      ]))
                                    : _createCommentVNode$2("", true)
                                ]),
                                _: 1
                              }),
                              _createVNode$2(_component_v_expand_transition, null, {
                                default: _withCtx$2(() => [
                                  (!proxy.value.network || proxy.value.network === 'tcp')
                                    ? (_openBlock$2(), _createElementBlock$1("div", _hoisted_6$1, [
                                        _createVNode$2(_component_v_card, { variant: "tonal" }, {
                                          default: _withCtx$2(() => [
                                            _createVNode$2(_component_v_card_title, { class: "text-subtitle-1 py-2" }, {
                                              default: _withCtx$2(() => _cache[53] || (_cache[53] = [
                                                _createTextVNode$2("Smux 选项")
                                              ])),
                                              _: 1
                                            }),
                                            _createVNode$2(_component_v_card_text, null, {
                                              default: _withCtx$2(() => [
                                                _createVNode$2(_component_v_row, { dense: "" }, {
                                                  default: _withCtx$2(() => [
                                                    _createVNode$2(_component_v_col, { cols: "12" }, {
                                                      default: _withCtx$2(() => [
                                                        _createVNode$2(_component_v_switch, {
                                                          modelValue: proxy.value.smux.enabled,
                                                          "onUpdate:modelValue": _cache[32] || (_cache[32] = $event => ((proxy.value.smux.enabled) = $event)),
                                                          label: "启用 Smux",
                                                          inset: "",
                                                          color: "primary"
                                                        }, null, 8, ["modelValue"])
                                                      ]),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 1
                                                }),
                                                _createVNode$2(_component_v_expand_transition, null, {
                                                  default: _withCtx$2(() => [
                                                    (proxy.value.smux.enabled)
                                                      ? (_openBlock$2(), _createElementBlock$1("div", _hoisted_7$1, [
                                                          _createVNode$2(_component_v_row, { dense: "" }, {
                                                            default: _withCtx$2(() => [
                                                              _createVNode$2(_component_v_col, {
                                                                cols: "12",
                                                                md: "6"
                                                              }, {
                                                                default: _withCtx$2(() => [
                                                                  _createVNode$2(_component_v_select, {
                                                                    modelValue: proxy.value.smux.protocol,
                                                                    "onUpdate:modelValue": _cache[33] || (_cache[33] = $event => ((proxy.value.smux.protocol) = $event)),
                                                                    label: "协议 (protocol)",
                                                                    items: ['smux', 'yamux', 'h2mux'],
                                                                    hint: "Smux协议类型",
                                                                    variant: "outlined"
                                                                  }, null, 8, ["modelValue"])
                                                                ]),
                                                                _: 1
                                                              }),
                                                              _createVNode$2(_component_v_col, {
                                                                cols: "12",
                                                                md: "6"
                                                              }, {
                                                                default: _withCtx$2(() => [
                                                                  _createVNode$2(_component_v_text_field, {
                                                                    modelValue: proxy.value.smux['max-connections'],
                                                                    "onUpdate:modelValue": _cache[34] || (_cache[34] = $event => ((proxy.value.smux['max-connections']) = $event)),
                                                                    modelModifiers: { number: true },
                                                                    label: "最大连接数 (max-connections)",
                                                                    type: "number",
                                                                    hint: "最大复用连接数",
                                                                    clearable: "",
                                                                    variant: "outlined"
                                                                  }, null, 8, ["modelValue"])
                                                                ]),
                                                                _: 1
                                                              }),
                                                              _createVNode$2(_component_v_col, {
                                                                cols: "12",
                                                                md: "6"
                                                              }, {
                                                                default: _withCtx$2(() => [
                                                                  _createVNode$2(_component_v_text_field, {
                                                                    modelValue: proxy.value.smux['min-streams'],
                                                                    "onUpdate:modelValue": _cache[35] || (_cache[35] = $event => ((proxy.value.smux['min-streams']) = $event)),
                                                                    modelModifiers: { number: true },
                                                                    label: "最小流数 (min-streams)",
                                                                    type: "number",
                                                                    hint: "每个连接的最小流数",
                                                                    clearable: "",
                                                                    variant: "outlined"
                                                                  }, null, 8, ["modelValue"])
                                                                ]),
                                                                _: 1
                                                              }),
                                                              _createVNode$2(_component_v_col, {
                                                                cols: "12",
                                                                md: "6"
                                                              }, {
                                                                default: _withCtx$2(() => [
                                                                  _createVNode$2(_component_v_text_field, {
                                                                    modelValue: proxy.value.smux['max-streams'],
                                                                    "onUpdate:modelValue": _cache[36] || (_cache[36] = $event => ((proxy.value.smux['max-streams']) = $event)),
                                                                    modelModifiers: { number: true },
                                                                    label: "最大流数 (max-streams)",
                                                                    type: "number",
                                                                    hint: "每个连接的最大流数",
                                                                    clearable: "",
                                                                    variant: "outlined"
                                                                  }, null, 8, ["modelValue"])
                                                                ]),
                                                                _: 1
                                                              }),
                                                              _createVNode$2(_component_v_col, {
                                                                cols: "4",
                                                                sm: "4"
                                                              }, {
                                                                default: _withCtx$2(() => [
                                                                  _createVNode$2(_component_v_switch, {
                                                                    modelValue: proxy.value.smux.padding,
                                                                    "onUpdate:modelValue": _cache[37] || (_cache[37] = $event => ((proxy.value.smux.padding) = $event)),
                                                                    label: "Padding",
                                                                    hint: "启用Padding",
                                                                    inset: "",
                                                                    color: "primary"
                                                                  }, null, 8, ["modelValue"])
                                                                ]),
                                                                _: 1
                                                              }),
                                                              _createVNode$2(_component_v_col, {
                                                                cols: "4",
                                                                sm: "4"
                                                              }, {
                                                                default: _withCtx$2(() => [
                                                                  _createVNode$2(_component_v_switch, {
                                                                    modelValue: proxy.value.smux.statistic,
                                                                    "onUpdate:modelValue": _cache[38] || (_cache[38] = $event => ((proxy.value.smux.statistic) = $event)),
                                                                    label: "Statistic",
                                                                    hint: "启用统计",
                                                                    inset: "",
                                                                    color: "primary"
                                                                  }, null, 8, ["modelValue"])
                                                                ]),
                                                                _: 1
                                                              }),
                                                              _createVNode$2(_component_v_col, {
                                                                cols: "4",
                                                                sm: "4"
                                                              }, {
                                                                default: _withCtx$2(() => [
                                                                  _createVNode$2(_component_v_switch, {
                                                                    modelValue: proxy.value.smux['only-tcp'],
                                                                    "onUpdate:modelValue": _cache[39] || (_cache[39] = $event => ((proxy.value.smux['only-tcp']) = $event)),
                                                                    label: "Only TCP",
                                                                    hint: "仅用于TCP",
                                                                    inset: "",
                                                                    color: "primary"
                                                                  }, null, 8, ["modelValue"])
                                                                ]),
                                                                _: 1
                                                              }),
                                                              _createVNode$2(_component_v_col, { cols: "12" }, {
                                                                default: _withCtx$2(() => [
                                                                  _createVNode$2(_component_v_switch, {
                                                                    modelValue: proxy.value.smux['brutal-opts'].enabled,
                                                                    "onUpdate:modelValue": _cache[40] || (_cache[40] = $event => ((proxy.value.smux['brutal-opts'].enabled) = $event)),
                                                                    label: "启用 Brutal 优化",
                                                                    inset: "",
                                                                    color: "primary"
                                                                  }, null, 8, ["modelValue"])
                                                                ]),
                                                                _: 1
                                                              })
                                                            ]),
                                                            _: 1
                                                          }),
                                                          _createVNode$2(_component_v_expand_transition, null, {
                                                            default: _withCtx$2(() => [
                                                              (proxy.value.smux['brutal-opts'].enabled)
                                                                ? (_openBlock$2(), _createBlock$2(_component_v_row, {
                                                                    key: 0,
                                                                    dense: ""
                                                                  }, {
                                                                    default: _withCtx$2(() => [
                                                                      _createVNode$2(_component_v_col, {
                                                                        cols: "12",
                                                                        md: "6"
                                                                      }, {
                                                                        default: _withCtx$2(() => [
                                                                          _createVNode$2(_component_v_text_field, {
                                                                            modelValue: proxy.value.smux['brutal-opts'].up,
                                                                            "onUpdate:modelValue": _cache[41] || (_cache[41] = $event => ((proxy.value.smux['brutal-opts'].up) = $event)),
                                                                            modelModifiers: { number: true },
                                                                            label: "上行带宽 (up)",
                                                                            hint: "上行带宽, 默认以 Mbps 为单位",
                                                                            clearable: "",
                                                                            variant: "outlined"
                                                                          }, null, 8, ["modelValue"])
                                                                        ]),
                                                                        _: 1
                                                                      }),
                                                                      _createVNode$2(_component_v_col, {
                                                                        cols: "12",
                                                                        md: "6"
                                                                      }, {
                                                                        default: _withCtx$2(() => [
                                                                          _createVNode$2(_component_v_text_field, {
                                                                            modelValue: proxy.value.smux['brutal-opts'].down,
                                                                            "onUpdate:modelValue": _cache[42] || (_cache[42] = $event => ((proxy.value.smux['brutal-opts'].down) = $event)),
                                                                            modelModifiers: { number: true },
                                                                            label: "下行带宽 (down)",
                                                                            hint: "下行带宽, 默认以 Mbps 为单位",
                                                                            clearable: "",
                                                                            variant: "outlined"
                                                                          }, null, 8, ["modelValue"])
                                                                        ]),
                                                                        _: 1
                                                                      })
                                                                    ]),
                                                                    _: 1
                                                                  }))
                                                                : _createCommentVNode$2("", true)
                                                            ]),
                                                            _: 1
                                                          })
                                                        ]))
                                                      : _createCommentVNode$2("", true)
                                                  ]),
                                                  _: 1
                                                })
                                              ]),
                                              _: 1
                                            })
                                          ]),
                                          _: 1
                                        })
                                      ]))
                                    : _createCommentVNode$2("", true)
                                ]),
                                _: 1
                              })
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"])
                ]),
                _: 1
              }, 512),
              _createVNode$2(_component_v_alert, {
                type: "info",
                text: "",
                variant: "tonal"
              }, {
                default: _withCtx$2(() => _cache[54] || (_cache[54] = [
                  _createTextVNode$2(" 参考"),
                  _createElementVNode$1("a", {
                    href: "https://wiki.metacubex.one/config/proxies/",
                    target: "_blank",
                    style: {"text-decoration":"underline"}
                  }, "Docs", -1),
                  _createTextVNode$2(", 覆写某些选项可能导致代理不可用。 ")
                ])),
                _: 1
              })
            ]),
            _: 1
          }),
          _createVNode$2(_component_v_card_actions, null, {
            default: _withCtx$2(() => [
              _createVNode$2(_component_v_checkbox, {
                modelValue: proxy.value.rescind,
                "onUpdate:modelValue": _cache[44] || (_cache[44] = $event => ((proxy.value.rescind) = $event)),
                label: "删除覆写"
              }, null, 8, ["modelValue"]),
              _createVNode$2(_component_v_spacer),
              _createVNode$2(_component_v_btn, {
                text: "",
                onClick: handleCancel
              }, {
                default: _withCtx$2(() => _cache[55] || (_cache[55] = [
                  _createTextVNode$2("取消")
                ])),
                _: 1
              }),
              _createVNode$2(_component_v_btn, {
                color: "primary",
                loading: __props.loading,
                disabled: __props.loading,
                onClick: handleSave
              }, {
                default: _withCtx$2(() => _cache[56] || (_cache[56] = [
                  _createTextVNode$2("保存")
                ])),
                _: 1
              }, 8, ["loading", "disabled"])
            ]),
            _: 1
          })
        ]),
        _: 1
      })
    ]),
    _: 1
  }, 8, ["modelValue"]))
}
}

};
const ProxiesDialog = /*#__PURE__*/_export_sfc(_sfc_main$2, [['__scopeId',"data-v-5b19bb19"]]);

/**
 * lodash (Custom Build) <https://lodash.com/>
 * Build: `lodash modularize exports="npm" -o ./`
 * Copyright jQuery Foundation and other contributors <https://jquery.org/>
 * Released under MIT license <https://lodash.com/license>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 */

/** Used as the `TypeError` message for "Functions" methods. */
var FUNC_ERROR_TEXT = 'Expected a function';

/** Used as references for various `Number` constants. */
var NAN = 0 / 0;

/** `Object#toString` result references. */
var symbolTag = '[object Symbol]';

/** Used to match leading and trailing whitespace. */
var reTrim = /^\s+|\s+$/g;

/** Used to detect bad signed hexadecimal string values. */
var reIsBadHex = /^[-+]0x[0-9a-f]+$/i;

/** Used to detect binary string values. */
var reIsBinary = /^0b[01]+$/i;

/** Used to detect octal string values. */
var reIsOctal = /^0o[0-7]+$/i;

/** Built-in method references without a dependency on `root`. */
var freeParseInt = parseInt;

/** Detect free variable `global` from Node.js. */
var freeGlobal = typeof commonjsGlobal == 'object' && commonjsGlobal && commonjsGlobal.Object === Object && commonjsGlobal;

/** Detect free variable `self`. */
var freeSelf = typeof self == 'object' && self && self.Object === Object && self;

/** Used as a reference to the global object. */
var root = freeGlobal || freeSelf || Function('return this')();

/** Used for built-in method references. */
var objectProto = Object.prototype;

/**
 * Used to resolve the
 * [`toStringTag`](http://ecma-international.org/ecma-262/7.0/#sec-object.prototype.tostring)
 * of values.
 */
var objectToString = objectProto.toString;

/* Built-in method references for those with the same name as other `lodash` methods. */
var nativeMax = Math.max,
    nativeMin = Math.min;

/**
 * Gets the timestamp of the number of milliseconds that have elapsed since
 * the Unix epoch (1 January 1970 00:00:00 UTC).
 *
 * @static
 * @memberOf _
 * @since 2.4.0
 * @category Date
 * @returns {number} Returns the timestamp.
 * @example
 *
 * _.defer(function(stamp) {
 *   console.log(_.now() - stamp);
 * }, _.now());
 * // => Logs the number of milliseconds it took for the deferred invocation.
 */
var now = function() {
  return root.Date.now();
};

/**
 * Creates a debounced function that delays invoking `func` until after `wait`
 * milliseconds have elapsed since the last time the debounced function was
 * invoked. The debounced function comes with a `cancel` method to cancel
 * delayed `func` invocations and a `flush` method to immediately invoke them.
 * Provide `options` to indicate whether `func` should be invoked on the
 * leading and/or trailing edge of the `wait` timeout. The `func` is invoked
 * with the last arguments provided to the debounced function. Subsequent
 * calls to the debounced function return the result of the last `func`
 * invocation.
 *
 * **Note:** If `leading` and `trailing` options are `true`, `func` is
 * invoked on the trailing edge of the timeout only if the debounced function
 * is invoked more than once during the `wait` timeout.
 *
 * If `wait` is `0` and `leading` is `false`, `func` invocation is deferred
 * until to the next tick, similar to `setTimeout` with a timeout of `0`.
 *
 * See [David Corbacho's article](https://css-tricks.com/debouncing-throttling-explained-examples/)
 * for details over the differences between `_.debounce` and `_.throttle`.
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @category Function
 * @param {Function} func The function to debounce.
 * @param {number} [wait=0] The number of milliseconds to delay.
 * @param {Object} [options={}] The options object.
 * @param {boolean} [options.leading=false]
 *  Specify invoking on the leading edge of the timeout.
 * @param {number} [options.maxWait]
 *  The maximum time `func` is allowed to be delayed before it's invoked.
 * @param {boolean} [options.trailing=true]
 *  Specify invoking on the trailing edge of the timeout.
 * @returns {Function} Returns the new debounced function.
 * @example
 *
 * // Avoid costly calculations while the window size is in flux.
 * jQuery(window).on('resize', _.debounce(calculateLayout, 150));
 *
 * // Invoke `sendMail` when clicked, debouncing subsequent calls.
 * jQuery(element).on('click', _.debounce(sendMail, 300, {
 *   'leading': true,
 *   'trailing': false
 * }));
 *
 * // Ensure `batchLog` is invoked once after 1 second of debounced calls.
 * var debounced = _.debounce(batchLog, 250, { 'maxWait': 1000 });
 * var source = new EventSource('/stream');
 * jQuery(source).on('message', debounced);
 *
 * // Cancel the trailing debounced invocation.
 * jQuery(window).on('popstate', debounced.cancel);
 */
function debounce(func, wait, options) {
  var lastArgs,
      lastThis,
      maxWait,
      result,
      timerId,
      lastCallTime,
      lastInvokeTime = 0,
      leading = false,
      maxing = false,
      trailing = true;

  if (typeof func != 'function') {
    throw new TypeError(FUNC_ERROR_TEXT);
  }
  wait = toNumber(wait) || 0;
  if (isObject(options)) {
    leading = !!options.leading;
    maxing = 'maxWait' in options;
    maxWait = maxing ? nativeMax(toNumber(options.maxWait) || 0, wait) : maxWait;
    trailing = 'trailing' in options ? !!options.trailing : trailing;
  }

  function invokeFunc(time) {
    var args = lastArgs,
        thisArg = lastThis;

    lastArgs = lastThis = undefined;
    lastInvokeTime = time;
    result = func.apply(thisArg, args);
    return result;
  }

  function leadingEdge(time) {
    // Reset any `maxWait` timer.
    lastInvokeTime = time;
    // Start the timer for the trailing edge.
    timerId = setTimeout(timerExpired, wait);
    // Invoke the leading edge.
    return leading ? invokeFunc(time) : result;
  }

  function remainingWait(time) {
    var timeSinceLastCall = time - lastCallTime,
        timeSinceLastInvoke = time - lastInvokeTime,
        result = wait - timeSinceLastCall;

    return maxing ? nativeMin(result, maxWait - timeSinceLastInvoke) : result;
  }

  function shouldInvoke(time) {
    var timeSinceLastCall = time - lastCallTime,
        timeSinceLastInvoke = time - lastInvokeTime;

    // Either this is the first call, activity has stopped and we're at the
    // trailing edge, the system time has gone backwards and we're treating
    // it as the trailing edge, or we've hit the `maxWait` limit.
    return (lastCallTime === undefined || (timeSinceLastCall >= wait) ||
      (timeSinceLastCall < 0) || (maxing && timeSinceLastInvoke >= maxWait));
  }

  function timerExpired() {
    var time = now();
    if (shouldInvoke(time)) {
      return trailingEdge(time);
    }
    // Restart the timer.
    timerId = setTimeout(timerExpired, remainingWait(time));
  }

  function trailingEdge(time) {
    timerId = undefined;

    // Only invoke if we have `lastArgs` which means `func` has been
    // debounced at least once.
    if (trailing && lastArgs) {
      return invokeFunc(time);
    }
    lastArgs = lastThis = undefined;
    return result;
  }

  function cancel() {
    if (timerId !== undefined) {
      clearTimeout(timerId);
    }
    lastInvokeTime = 0;
    lastArgs = lastCallTime = lastThis = timerId = undefined;
  }

  function flush() {
    return timerId === undefined ? result : trailingEdge(now());
  }

  function debounced() {
    var time = now(),
        isInvoking = shouldInvoke(time);

    lastArgs = arguments;
    lastThis = this;
    lastCallTime = time;

    if (isInvoking) {
      if (timerId === undefined) {
        return leadingEdge(lastCallTime);
      }
      if (maxing) {
        // Handle invocations in a tight loop.
        timerId = setTimeout(timerExpired, wait);
        return invokeFunc(lastCallTime);
      }
    }
    if (timerId === undefined) {
      timerId = setTimeout(timerExpired, wait);
    }
    return result;
  }
  debounced.cancel = cancel;
  debounced.flush = flush;
  return debounced;
}

/**
 * Checks if `value` is the
 * [language type](http://www.ecma-international.org/ecma-262/7.0/#sec-ecmascript-language-types)
 * of `Object`. (e.g. arrays, functions, objects, regexes, `new Number(0)`, and `new String('')`)
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is an object, else `false`.
 * @example
 *
 * _.isObject({});
 * // => true
 *
 * _.isObject([1, 2, 3]);
 * // => true
 *
 * _.isObject(_.noop);
 * // => true
 *
 * _.isObject(null);
 * // => false
 */
function isObject(value) {
  var type = typeof value;
  return !!value && (type == 'object' || type == 'function');
}

/**
 * Checks if `value` is object-like. A value is object-like if it's not `null`
 * and has a `typeof` result of "object".
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
 * @example
 *
 * _.isObjectLike({});
 * // => true
 *
 * _.isObjectLike([1, 2, 3]);
 * // => true
 *
 * _.isObjectLike(_.noop);
 * // => false
 *
 * _.isObjectLike(null);
 * // => false
 */
function isObjectLike(value) {
  return !!value && typeof value == 'object';
}

/**
 * Checks if `value` is classified as a `Symbol` primitive or object.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a symbol, else `false`.
 * @example
 *
 * _.isSymbol(Symbol.iterator);
 * // => true
 *
 * _.isSymbol('abc');
 * // => false
 */
function isSymbol(value) {
  return typeof value == 'symbol' ||
    (isObjectLike(value) && objectToString.call(value) == symbolTag);
}

/**
 * Converts `value` to a number.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to process.
 * @returns {number} Returns the number.
 * @example
 *
 * _.toNumber(3.2);
 * // => 3.2
 *
 * _.toNumber(Number.MIN_VALUE);
 * // => 5e-324
 *
 * _.toNumber(Infinity);
 * // => Infinity
 *
 * _.toNumber('3.2');
 * // => 3.2
 */
function toNumber(value) {
  if (typeof value == 'number') {
    return value;
  }
  if (isSymbol(value)) {
    return NAN;
  }
  if (isObject(value)) {
    var other = typeof value.valueOf == 'function' ? value.valueOf() : value;
    value = isObject(other) ? (other + '') : other;
  }
  if (typeof value != 'string') {
    return value === 0 ? value : +value;
  }
  value = value.replace(reTrim, '');
  var isBinary = reIsBinary.test(value);
  return (isBinary || reIsOctal.test(value))
    ? freeParseInt(value.slice(2), isBinary ? 2 : 8)
    : (reIsBadHex.test(value) ? NAN : +value);
}

var lodash_debounce = debounce;

const debounce$1 = /*@__PURE__*/getDefaultExportFromCjs(lodash_debounce);

const {toDisplayString:_toDisplayString$1,createTextVNode:_createTextVNode$1,resolveComponent:_resolveComponent$1,withCtx:_withCtx$1,createVNode:_createVNode$1,openBlock:_openBlock$1,createBlock:_createBlock$1,createCommentVNode:_createCommentVNode$1,withModifiers:_withModifiers$1} = await importShared('vue');


const {ref: ref$1,computed: computed$1} = await importShared('vue');


const _sfc_main$1 = {
  __name: 'RuleDialog',
  props: {
  // 父组件传递的规则数据
  initialRule: {
    type: Object,
    default: () => ({
      type: 'DOMAIN',
      payload: null,
      action: 'DIRECT',
      priority: 0,
      additional_params: null,
      conditions: [],
      condition: null
    })
  },
  // 控制对话框的显示与隐藏
  showDialog: {
    type: Boolean,
    default: false
  },
  isAddingRule: {
    type: Boolean,
    default: true
  },
  editingType: {
    type: String,
    default: 'top'
  },
  ruleProviderNames: {
    type: Array,
    default: () => []
  },
  geoIp: {
    type: Array,
    default: () => []
  },
  geoSite: {
    type: Array,
    default: () => []
  },
  customOutbounds: {
    type: Array,
    default: () => []
  },
  loading: {
    type: Boolean,
    default: false
  }
},
  emits: ['save', 'update:showDialog'],
  setup(__props, { emit: __emit }) {


const ruleForm = ref$1(null);
const geoSearch = ref$1('');
const geoIPSearch = ref$1('');
const geoFilterLoading = ref$1(false);
const filteredGeoItems = ref$1([]);
const ruleTypes = computed$1(() => {
  const allTypes = [
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX', 'DOMAIN-WILDCARD', 'GEOSITE', 'GEOIP',
    'IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'IP-ASN',
    'SRC-GEOIP', 'SRC-IP-ASN', 'SRC-IP-CIDR', 'SRC-IP-SUFFIX',
    'DST-PORT', 'SRC-PORT', 'IN-PORT', 'IN-TYPE', 'IN-USER', 'IN-NAME',
    'PROCESS-PATH', 'PROCESS-PATH-REGEX', 'PROCESS-NAME', 'PROCESS-NAME-REGEX',
    'UID', 'NETWORK', 'DSCP', 'RULE-SET', 'AND', 'OR', 'NOT', 'SUB-RULE', 'MATCH'
  ];

  // 如果是 ruleset 规则，过滤掉 SUB-RULE 和 RULE-SET
  if (props.editingType.value === 'ruleset') {
    return allTypes.filter(type => !['SUB-RULE', 'RULE-SET'].includes(type));
  }
  return allTypes;
});
const showAdditionalParams = computed$1(() => {
  return ['IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP'].includes(rule.value.type);
});
const onGeoSearch = (val) => {
  geoSearch.value = val;
  performGeoSiteFilter(val);
};
const onGeoIPSearch = (val) => {
  geoIPSearch.value = val;
  performGeoIPFilter(val);
};
const performGeoSiteFilter = debounce$1((val) => {
  if (!val) {
    filteredGeoItems.value = [];
    geoFilterLoading.value = false;
    return
  }
  geoFilterLoading.value = true;
  filteredGeoItems.value = props.geoSite.filter(item =>
      item.toLowerCase().includes(val.toLowerCase())
  );
  geoFilterLoading.value = false;
}, 100); // 10ms debounce

const performGeoIPFilter = debounce$1((val) => {
  if (!val) {
    filteredGeoItems.value = [];
    geoFilterLoading.value = false;
    return
  }
  geoFilterLoading.value = true;
  filteredGeoItems.value = props.geoIp.filter(item =>
      item.toLowerCase().includes(val.toLowerCase())
  );
  geoFilterLoading.value = false;
}, 200); // 20ms debounce

// 当输入框失去焦点时，将当前搜索词设置为选中项（如果它不在候选列表中）
const onGeoSiteBlur = () => {
  if (!filteredGeoItems.value.includes(geoSearch.value)) {
    rule.value.payload = geoSearch.value;
  }
};
const onGeoIPBlur = () => {
  if (!filteredGeoItems.value.includes(geoIPSearch.value)) {
    rule.value.payload = geoIPSearch.value;
  }
};

const actions = computed$1(() => [
  'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE',
  ...props.customOutbounds.map(outbound => outbound.name)
]);

const additionalParamOptions = ref$1([
  {title: '无', value: ''},
  {title: 'no-resolve', value: 'no-resolve'},
  {title: 'src', value: 'src'}
]);


// 1. 定义 Props
// 使用 defineProps 宏。传入的参数与 defineComponent 的 props 选项内容相同
const props = __props;

// 2. 定义 Emits
// 使用 defineEmits 宏。传入一个字符串数组，列出组件会触发的事件
const emit = __emit;

// 3. 响应式数据
// 将 props 中的 initialRule 复制到 rule 中，以便在组件内部修改而不影响父组件的 prop
const rule = ref$1({...props.initialRule});

const show = computed$1({
  get: () => props.showDialog,
  set: (value) => emit('update:showDialog', value)
});


const payloadRules = computed$1(() => {
  return [
    (v) => {
      // 如果 type 是 'MATCH'，允许 payload 为空
      if (rule.value.type === 'MATCH') {
        return true; // 不验证
      }
      // 否则，payload 不能为空
      return !!v || '内容不能为空';
    },
  ];
});

// 4. 方法
// 提交表单
const submitForm = async () => {
  const {valid} = await ruleForm.value.validate();
  if (valid) {
    // 触发父组件的保存事件
    emit('save', rule.value);
    // 关闭对话框
    // emit('update:showDialog', false);
  }
};

// 关闭对话框
const closeDialog = () => {
  emit('update:showDialog', false);
};


return (_ctx, _cache) => {
  const _component_v_card_title = _resolveComponent$1("v-card-title");
  const _component_v_select = _resolveComponent$1("v-select");
  const _component_v_autocomplete = _resolveComponent$1("v-autocomplete");
  const _component_v_combobox = _resolveComponent$1("v-combobox");
  const _component_v_text_field = _resolveComponent$1("v-text-field");
  const _component_v_card_text = _resolveComponent$1("v-card-text");
  const _component_v_spacer = _resolveComponent$1("v-spacer");
  const _component_v_btn = _resolveComponent$1("v-btn");
  const _component_v_card_actions = _resolveComponent$1("v-card-actions");
  const _component_v_card = _resolveComponent$1("v-card");
  const _component_v_form = _resolveComponent$1("v-form");
  const _component_v_dialog = _resolveComponent$1("v-dialog");

  return (_openBlock$1(), _createBlock$1(_component_v_dialog, {
    modelValue: show.value,
    "onUpdate:modelValue": _cache[11] || (_cache[11] = $event => ((show).value = $event)),
    "max-width": "40rem"
  }, {
    default: _withCtx$1(() => [
      _createVNode$1(_component_v_form, {
        ref_key: "ruleForm",
        ref: ruleForm,
        onSubmit: _withModifiers$1(submitForm, ["prevent"])
      }, {
        default: _withCtx$1(() => [
          _createVNode$1(_component_v_card, null, {
            default: _withCtx$1(() => [
              _createVNode$1(_component_v_card_title, null, {
                default: _withCtx$1(() => [
                  _createTextVNode$1(_toDisplayString$1(props.isAddingRule ? '添加规则' : '编辑规则'), 1)
                ]),
                _: 1
              }),
              _createVNode$1(_component_v_card_text, null, {
                default: _withCtx$1(() => [
                  _createVNode$1(_component_v_select, {
                    modelValue: rule.value.type,
                    "onUpdate:modelValue": _cache[0] || (_cache[0] = $event => ((rule.value.type) = $event)),
                    items: ruleTypes.value,
                    label: "规则类型",
                    required: "",
                    class: "mb-4"
                  }, null, 8, ["modelValue", "items"]),
                  (rule.value.type === 'RULE-SET')
                    ? (_openBlock$1(), _createBlock$1(_component_v_select, {
                        key: 0,
                        modelValue: rule.value.payload,
                        "onUpdate:modelValue": _cache[1] || (_cache[1] = $event => ((rule.value.payload) = $event)),
                        items: props.ruleProviderNames,
                        label: "选择规则集",
                        required: "",
                        rules: [(v) => !!v || '请选择一个有效的规则集',],
                        class: "mb-4"
                      }, null, 8, ["modelValue", "items", "rules"]))
                    : (rule.value.type === 'GEOSITE')
                      ? (_openBlock$1(), _createBlock$1(_component_v_autocomplete, {
                          key: 1,
                          modelValue: rule.value.payload,
                          "onUpdate:modelValue": _cache[2] || (_cache[2] = $event => ((rule.value.payload) = $event)),
                          search: geoSearch.value,
                          items: filteredGeoItems.value,
                          loading: geoFilterLoading.value,
                          "hide-no-data": "",
                          "hide-selected": "",
                          label: "内容",
                          "no-filter": "",
                          solo: "",
                          "custom-filter": () => true,
                          clearable: "",
                          "onUpdate:search": onGeoSearch,
                          onBlur: onGeoSiteBlur,
                          class: "mb-4",
                          rules: payloadRules.value
                        }, null, 8, ["modelValue", "search", "items", "loading", "rules"]))
                      : (rule.value.type === 'GEOIP')
                        ? (_openBlock$1(), _createBlock$1(_component_v_autocomplete, {
                            key: 2,
                            modelValue: rule.value.payload,
                            "onUpdate:modelValue": _cache[3] || (_cache[3] = $event => ((rule.value.payload) = $event)),
                            search: geoIPSearch.value,
                            items: filteredGeoItems.value,
                            loading: geoFilterLoading.value,
                            "hide-no-data": "",
                            "hide-selected": "",
                            label: "内容",
                            "no-filter": "",
                            solo: "",
                            "custom-filter": () => true,
                            clearable: "",
                            "onUpdate:search": onGeoIPSearch,
                            onBlur: onGeoIPBlur,
                            class: "mb-4",
                            rules: payloadRules.value
                          }, null, 8, ["modelValue", "search", "items", "loading", "rules"]))
                        : (rule.value.type === 'AND' || rule.value.type === 'OR' || rule.value.type === 'NOT')
                          ? (_openBlock$1(), _createBlock$1(_component_v_combobox, {
                              key: 3,
                              modelValue: rule.value.conditions,
                              "onUpdate:modelValue": _cache[4] || (_cache[4] = $event => ((rule.value.conditions) = $event)),
                              label: "条件",
                              multiple: "",
                              chips: "",
                              hint: "(DOMAIN,baidu.com) (NETWORK,TCP)",
                              clearable: "",
                              required: "",
                              class: "mb-4"
                            }, null, 8, ["modelValue"]))
                          : (rule.value.type === 'SUB-RULE')
                            ? (_openBlock$1(), _createBlock$1(_component_v_text_field, {
                                key: 4,
                                modelValue: rule.value.condition,
                                "onUpdate:modelValue": _cache[5] || (_cache[5] = $event => ((rule.value.condition) = $event)),
                                label: "条件",
                                required: "",
                                placeholder: "(AND,(DOMAIN,baidu.com),(NETWORK,TCP))",
                                rules: payloadRules.value,
                                class: "mb-4"
                              }, null, 8, ["modelValue", "rules"]))
                            : (_openBlock$1(), _createBlock$1(_component_v_text_field, {
                                key: 5,
                                modelValue: rule.value.payload,
                                "onUpdate:modelValue": _cache[6] || (_cache[6] = $event => ((rule.value.payload) = $event)),
                                label: "内容",
                                required: "",
                                rules: payloadRules.value,
                                class: "mb-4"
                              }, null, 8, ["modelValue", "rules"])),
                  (rule.value.type === 'SUB-RULE')
                    ? (_openBlock$1(), _createBlock$1(_component_v_text_field, {
                        key: 6,
                        modelValue: rule.value.action,
                        "onUpdate:modelValue": _cache[7] || (_cache[7] = $event => ((rule.value.action) = $event)),
                        label: "子规则",
                        required: "",
                        class: "mb-4"
                      }, null, 8, ["modelValue"]))
                    : (_openBlock$1(), _createBlock$1(_component_v_select, {
                        key: 7,
                        modelValue: rule.value.action,
                        "onUpdate:modelValue": _cache[8] || (_cache[8] = $event => ((rule.value.action) = $event)),
                        items: actions.value,
                        label: "出站",
                        required: "",
                        class: "mb-4"
                      }, null, 8, ["modelValue", "items"])),
                  (showAdditionalParams.value)
                    ? (_openBlock$1(), _createBlock$1(_component_v_select, {
                        key: 8,
                        modelValue: rule.value.additional_params,
                        "onUpdate:modelValue": _cache[9] || (_cache[9] = $event => ((rule.value.additional_params) = $event)),
                        label: "附加参数",
                        items: additionalParamOptions.value,
                        clearable: "",
                        hint: "可选参数",
                        "persistent-hint": "",
                        class: "mb-4"
                      }, null, 8, ["modelValue", "items"]))
                    : _createCommentVNode$1("", true),
                  _createVNode$1(_component_v_text_field, {
                    modelValue: rule.value.priority,
                    "onUpdate:modelValue": _cache[10] || (_cache[10] = $event => ((rule.value.priority) = $event)),
                    modelModifiers: { number: true },
                    type: "number",
                    label: "优先级",
                    hint: "数字越小优先级越高",
                    "persistent-hint": ""
                  }, null, 8, ["modelValue"])
                ]),
                _: 1
              }),
              _createVNode$1(_component_v_card_actions, null, {
                default: _withCtx$1(() => [
                  _createVNode$1(_component_v_spacer),
                  _createVNode$1(_component_v_btn, {
                    color: "secondary",
                    onClick: closeDialog
                  }, {
                    default: _withCtx$1(() => _cache[12] || (_cache[12] = [
                      _createTextVNode$1("取消")
                    ])),
                    _: 1
                  }),
                  _createVNode$1(_component_v_btn, {
                    color: "primary",
                    type: "submit",
                    loading: props.loading
                  }, {
                    default: _withCtx$1(() => _cache[13] || (_cache[13] = [
                      _createTextVNode$1("保存 ")
                    ])),
                    _: 1
                  }, 8, ["loading"])
                ]),
                _: 1
              })
            ]),
            _: 1
          })
        ]),
        _: 1
      }, 512)
    ]),
    _: 1
  }, 8, ["modelValue"]))
}
}

};

const {toDisplayString:_toDisplayString,createTextVNode:_createTextVNode,resolveComponent:_resolveComponent,withCtx:_withCtx,openBlock:_openBlock,createBlock:_createBlock,createCommentVNode:_createCommentVNode,createElementVNode:_createElementVNode,createVNode:_createVNode,createElementBlock:_createElementBlock,withModifiers:_withModifiers,normalizeClass:_normalizeClass,renderList:_renderList,Fragment:_Fragment,mergeProps:_mergeProps,unref:_unref} = await importShared('vue');


const _hoisted_1 = { class: "plugin-page" };
const _hoisted_2 = ["src"];
const _hoisted_3 = { key: 1 };
const _hoisted_4 = { class: "mb-2" };
const _hoisted_5 = { class: "pa-4" };
const _hoisted_6 = { class: "d-none d-sm-flex clash-data-table" };
const _hoisted_7 = ["onDragstart", "onDragover", "onDrop"];
const _hoisted_8 = { key: 0 };
const _hoisted_9 = { key: 1 };
const _hoisted_10 = { class: "d-sm-none" };
const _hoisted_11 = { class: "font-weight-bold" };
const _hoisted_12 = { class: "text-body-2" };
const _hoisted_13 = { class: "text-body-2" };
const _hoisted_14 = { class: "text-body-2" };
const _hoisted_15 = {
  class: "pa-4",
  style: {"min-height":"4rem"}
};
const _hoisted_16 = { class: "mb-2" };
const _hoisted_17 = { class: "pa-4" };
const _hoisted_18 = { class: "d-none d-sm-flex clash-data-table" };
const _hoisted_19 = ["onDragstart", "onDragover", "onDrop"];
const _hoisted_20 = { key: 0 };
const _hoisted_21 = { key: 1 };
const _hoisted_22 = { class: "d-sm-none" };
const _hoisted_23 = { class: "font-weight-bold" };
const _hoisted_24 = { class: "text-body-2" };
const _hoisted_25 = { class: "text-body-2" };
const _hoisted_26 = {
  class: "pa-4",
  style: {"min-height":"4rem"}
};
const _hoisted_27 = { class: "mb-2" };
const _hoisted_28 = { class: "pa-4" };
const _hoisted_29 = { class: "d-none d-sm-flex clash-data-table" };
const _hoisted_30 = { class: "d-sm-none" };
const _hoisted_31 = { class: "font-weight-bold" };
const _hoisted_32 = { class: "text-body-2" };
const _hoisted_33 = {
  class: "pa-4",
  style: {"min-height":"4rem"}
};
const _hoisted_34 = { class: "mb-2" };
const _hoisted_35 = { class: "pa-4" };
const _hoisted_36 = { class: "d-none d-sm-flex clash-data-table" };
const _hoisted_37 = { class: "d-sm-none" };
const _hoisted_38 = { class: "font-weight-bold" };
const _hoisted_39 = { class: "text-body-2" };
const _hoisted_40 = { class: "text-body-2" };
const _hoisted_41 = {
  class: "pa-4",
  style: {"min-height":"4rem"}
};
const _hoisted_42 = { class: "mb-2" };
const _hoisted_43 = { class: "pa-4" };
const _hoisted_44 = { class: "d-none d-sm-flex clash-data-table" };
const _hoisted_45 = { class: "d-sm-none" };
const _hoisted_46 = { class: "font-weight-bold" };
const _hoisted_47 = { class: "text-body-2" };
const _hoisted_48 = { class: "text-body-2" };
const _hoisted_49 = {
  class: "pa-4",
  style: {"min-height":"4rem"}
};
const _hoisted_50 = { class: "mb-2" };
const _hoisted_51 = { class: "pa-4" };
const _hoisted_52 = { class: "d-none d-sm-flex clash-data-table" };
const _hoisted_53 = { class: "d-sm-none" };
const _hoisted_54 = { class: "font-weight-bold" };
const _hoisted_55 = { class: "text-body-2" };
const _hoisted_56 = {
  class: "pa-4",
  style: {"min-height":"4rem"}
};
const _hoisted_57 = { class: "mb-2" };
const _hoisted_58 = { class: "card-header" };
const _hoisted_59 = { class: "mb-2" };
const _hoisted_60 = { class: "d-flex justify-space-between mb-2" };
const _hoisted_61 = { class: "d-flex justify-space-between mb-2" };
const _hoisted_62 = { class: "d-flex py-2 justify-space-between text-caption text-grey" };
const _hoisted_63 = { class: "toggle-container" };
const _hoisted_64 = { key: 0 };
const _hoisted_65 = { class: "text-h6 mt-2 font-weight-bold" };
const _hoisted_66 = { class: "text-h6 mt-2 font-weight-bold" };
const _hoisted_67 = { class: "text-h6 mt-2 font-weight-bold" };
const _hoisted_68 = { class: "text-h6 mt-2 font-weight-bold" };
const _hoisted_69 = { class: "text-h6 mt-2 font-weight-bold" };
const _hoisted_70 = { class: "text-h6 mt-2 font-weight-bold" };
const _hoisted_71 = { class: "text-h6 mt-2 font-weight-bold" };
const _hoisted_72 = { class: "text-h6 mt-2 font-weight-bold" };

const {ref,onMounted,computed} = await importShared('vue');


const _sfc_main = {
  __name: 'Page',
  props: {
  model: {
    type: Object,
    default: () => {
    },
  },
  api: {
    type: Object,
    default: () => {
    },
  },
},
  emits: ['action', 'switch', 'close'],
  setup(__props, { emit: __emit }) {

const editorOptions = {
  enableBasicAutocompletion: true,
  enableSnippets: true,
  enableLiveAutocompletion: true,
  showLineNumbers: true,
  tabSize: 2
};

const readOnlyEditorOptions = {
  readOnly: true,
  ...editorOptions.value,
};

const proxiesPlaceholder = ref(
    `proxies:
  - name: "ss node"
    type: "ss"`
);
const rulesPlaceholder = ref(
    `rules:
  - DOMAIN,gemini.google.com,Openai`
);
// v-data-table 的 headers 定义
const headers = ref([
  {title: '优先级', key: 'priority', sortable: true}, // 可以根据需要设置是否可排序
  {title: '类型', key: 'type', sortable: true},
  {title: '内容', key: 'payload', sortable: true},
  {title: '出站', key: 'action', sortable: false},
  {title: '日期', key: 'time_modified', sortable: true},
  {title: '操作', key: 'actions', sortable: false},
]);

const headersRuleset = ref([
  {title: '优先级', key: 'priority', sortable: true},
  {title: '类型', key: 'type', sortable: true},
  {title: '内容', key: 'payload', sortable: true},
  {title: '出站', key: 'action', sortable: true},
  {title: '规则集合名', key: 'name', sortable: true},
  {title: '日期', key: 'time_modified', sortable: true},
  {title: '操作', key: 'actions', sortable: false},
]);

const headersRuleProviders = ref([
  {title: '名称', key: 'name', sortable: true},
  {title: '类型', key: 'type', sortable: true},
  {title: '行为', key: 'behavior', sortable: false},
  {title: '格式', key: 'format', sortable: false},
  {title: '来源', key: 'source', sortable: false},
  {title: '操作', key: 'actions', sortable: false},
]);

const headersHosts = ref([
  {title: '域名', key: 'domain', sortable: true},
  {title: 'IP', key: 'value', sortable: false},
  {title: 'Cloudflare CDN', key: 'using_cloudflare', sortable: false},
  {title: '操作', key: 'actions', sortable: false},
]);

const proxyGroupHeaders = ref([
  {title: '名称', key: 'name', sortable: true},
  {title: '类型', key: 'type', sortable: false},
  {title: '来源', key: 'source', sortable: false},
  {title: '操作', key: 'actions', sortable: false},
]);
const extraProxiesHeaders = ref([
  {title: '名称', key: 'name', sortable: true},
  {title: '类型', key: 'type', sortable: false},
  {title: '服务器', key: 'server', sortable: false},
  {title: '端口', key: 'port', sortable: false},
  {title: '来源', key: 'source', sortable: false},
  {title: '操作', key: 'actions', sortable: false},
]);
const activeTab = ref(0);
const page = ref(1);
const pageRuleset = ref(1);
const pageRulProviders = ref(1);
const pageHosts = ref(1);
const pageProxyGroup = ref(1);
const pageExtraProxies = ref(1);
const itemsPerPage = ref(10); // v-data-table 默认的 items-per-page 值
const itemsPerPageRuleset = ref(10);
const itemsPerPageRuleProviders = ref(10);
const itemsPerPageHosts = ref(10);
const itemsPerPageProxyGroup = ref(10);
const itemsPerPageExtraProxies = ref(10);
const itemsPerPageOptions = ref([
  {title: '5', value: 5},
  {title: '10', value: 10},
  {title: '20', value: 20},
  {title: '50', value: 50},
  {title: 'All', value: -1},
]);

const pageCount = computed(() => {
  if (itemsPerPage.value === -1) {
    return 1;
  }
  return Math.ceil(filteredRules.value.length / itemsPerPage.value);
});

const filteredRules = computed(() => {
  // 模拟 Vuetify 内部的 search 逻辑
  if (!searchTopRule.value) return sortedRules.value;
  const keyword = searchTopRule.value.toLowerCase();
  return sortedRules.value.filter(item =>
      Object.values(item).some(val =>
          String(val).toLowerCase().includes(keyword)
      )
  );
});

const paginatedTopRules = computed(() => {
  const start = (page.value - 1) * itemsPerPage.value;
  const end = start + itemsPerPage.value;
  return filteredRules.value.slice(start, end)
});

const filteredRulesetRules = computed(() => {
  if (!searchRulesetRule.value) return sortedRulesetRules.value;
  const keyword = searchRulesetRule.value.toLowerCase();
  return sortedRulesetRules.value.filter(item =>
      Object.values(item).some(val =>
          String(val).toLowerCase().includes(keyword)
      )
  );
});

const filteredProxyGroups = computed(() => {
  if (!searchProxyGroups.value) return proxyGroups.value;
  const keyword = searchProxyGroups.value.toLowerCase();
  return proxyGroups.value.filter(item =>
      Object.values(item).some(val =>
          String(val).toLowerCase().includes(keyword)
      )
  );
});

const filteredExtraProxies = computed(() => {
  if (!searchExtraProxies.value) return extraProxies.value;
  const keyword = searchExtraProxies.value.toLowerCase();
  return extraProxies.value.filter(item =>
      Object.values(item).some(val =>
          String(val).toLowerCase().includes(keyword)
      )
  );
});

const filteredExtraRuleProviders = computed(() => {
  if (!searchRuleProviders.value) return extraRuleProviders.value;
  const keyword = searchRuleProviders.value.toLowerCase();
  return extraRuleProviders.value.filter(item =>
      Object.values(item).some(val =>
          String(val).toLowerCase().includes(keyword)
      )
  );
});

const filteredHosts = computed(() => {
  if (!searchHosts.value) return hosts.value;
  const keyword = searchHosts.value.toLowerCase();
  return hosts.value.filter(item =>
      Object.values(item).some(val =>
          String(val).toLowerCase().includes(keyword)
      )
  );
});

const paginatedHosts = computed(() => {
  const start = (pageHosts.value - 1) * itemsPerPageHosts.value;
  const end = start + itemsPerPageHosts.value;
  return filteredHosts.value.slice(start, end)
});

const paginatedExtraRuleProviders = computed(() => {
  const start = (pageRulProviders.value - 1) * itemsPerPageRuleProviders.value;
  const end = start + itemsPerPageRuleProviders.value;
  return filteredExtraRuleProviders.value.slice(start, end)
});

const paginatedExtraProxies = computed(() => {
  const start = (pageExtraProxies.value - 1) * itemsPerPageExtraProxies.value;
  const end = start + itemsPerPageExtraProxies.value;
  return filteredExtraProxies.value.slice(start, end)
});

const paginatedProxyGroups = computed(() => {
  const start = (pageProxyGroup.value - 1) * itemsPerPageProxyGroup.value;
  const end = start + itemsPerPageProxyGroup.value;
  return filteredProxyGroups.value.slice(start, end)
});

const paginatedRulesetRules = computed(() => {
  const start = (pageRuleset.value - 1) * itemsPerPageRuleset.value;
  const end = start + itemsPerPageRuleset.value;
  return filteredRulesetRules.value.slice(start, end)
});

const pageCountRuleset = computed(() => {
  if (itemsPerPageRuleset.value === -1) {
    return 1;
  }
  return Math.ceil(filteredRulesetRules.value.length / itemsPerPageRuleset.value);
});

const pageCountProxyGroups = computed(() => {
  if (itemsPerPageProxyGroup.value === -1) {
    return 1;
  }
  return Math.ceil(filteredProxyGroups.value.length / itemsPerPageProxyGroup.value);
});

const pageCountExtraProxies = computed(() => {
  if (itemsPerPageExtraProxies.value === -1) {
    return 1;
  }
  return Math.ceil(extraProxies.value.length / itemsPerPageExtraProxies.value);
});

const pageCountExtraRuleProviders = computed(() => {
  if (itemsPerPageRuleProviders.value === -1) {
    return 1;
  }
  return Math.ceil(extraRuleProviders.value.length / itemsPerPageRuleProviders.value);
});

const pageCountHosts = computed(() => {
  if (itemsPerPageHosts.value === -1) {
    return 1;
  }
  return Math.ceil(hosts.value.length / itemsPerPageHosts.value);
});

const snackbar = ref({
  show: false,
  message: '',
  color: 'success'
});
const dragItem = ref(null);
// 添加自定义出站状态
const customOutbounds = ref([]);


const subUrl = ref('');
const isValidUrl = (urlString) => {
  if (!urlString) return false;
  try {
    const url = new URL(urlString);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (e) {
    return false;
  }
};

// 定义验证规则数组
const urlRules = [
  (v) => {
    // 规则：值v可以为空 (falsy, 如''), 或者必须满足isValidUrl(v)的校验
    // 如果校验失败，则返回字符串作为错误提示
    return !v || isValidUrl(v) || '请输入一个有效的URL地址';
  }
];

function isValidIP(ip) {
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){1,7}|:):([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

function validateIPs(ips) {
  if (ips.length === 0) {
    return `至少需要一个 IP 地址`
  }
  for (const ip of ips) {
    if (!isValidIP(ip)) {
      return `无效的 IP 地址: ${ip}`
    }
  }
  return true
}

function dragStart(event, priority, type = 'top') {
  const currentRules = type === 'top' ? rules.value : rulesetRules.value;
  dragItem.value = currentRules.find(r => r.priority === priority);
  event.dataTransfer.effectAllowed = 'move';
}

function dragOver(event, priority, type = 'top') {
  event.preventDefault();
  const currentRules = type === 'top' ? rules.value : rulesetRules.value;
  // 高亮当前悬停行
  currentRules.forEach(rule => {
    rule._isHovered = (rule.priority === priority);
  });
}

async function drop(event, targetPriority, type = 'top') {
  // 5. 调用 API 提交
  await props.api.put(`/plugin/ClashRuleProvider/reorder-rules/${type}/${targetPriority}`, dragItem.value);
  dragItem.value = null;
  await refreshAllRegions(["top", "ruleset"]);
}

// 接收初始配置
const props = __props;

const proxyGroups = ref([]);
const proxyProviders = ref({});
const extraProxies = ref([]);
const newProxyGroup = ref({
  name: '',
  type: 'select',
  proxies: [],
  url: null,
  lazy: true,
  interval: 300,
  timeout: 5000,
  'disable-udp': false,
  filter: null,
  'include-all': false,
  'include-all-proxies': false,
  'include-all-providers': false,
  'exclude-filter': null,
  'exclude-type': null,
  tolerance: null,
  strategy: null,
  'expected-status': '*',
  hidden: false,
  icon: null,
  use: null,
  'max-failed-times': 5,
  'policy-priority': "1",
  uselightgbm: false,
  collectdata: false,
  'sample-rate': 1,

});

// 组件状态
const expand = ref(false);
const loading = ref(true);
const importProxiesLoading = ref(false);
const saveRuleLoading = ref(false);
const saveHostLoading = ref(false);
const saveProxyLoading = ref(false);
const saveRuleProviderLoading = ref(false);
const importRuleLoading = ref(false);
const saveProxyGroupLoading = ref(false);
const error = ref(null);
const errorMsg = ref('');
const rules = ref([]);
const rulesetRules = ref([]);
const extraRuleProviders = ref([]);
const hosts = ref([]);
const status = ref('running');
const rulesetPrefix = ref('📂<=');
const geoRules = ref({
  geoip: [],
  geosite: [],
});
const lastUpdated = ref('');
const refreshingSubscription = ref({});
const yamlDialog = ref(false);
const displayedYaml = ref('');
const searchTopRule = ref('');
const searchRulesetRule = ref('');
const searchRuleProviders = ref('');
const searchExtraProxies = ref('');
const searchProxyGroups = ref('');
const searchHosts = ref('');
// 规则编辑相关状态
const proxyGroupDialog = ref(false);
const ruleDialogVisible = ref(false);
const ruleProviderDialog = ref(false);
const hostDialog = ref(false);
const proxiesDialogVisible = ref(false);
const editingPriority = ref(null);
const editingProxyGroupName = ref(null);
const editingRuleProviderName = ref(null);
const editingHostDomainName = ref(null);
const editingType = ref('top'); // 记录当前编辑的规则类型（'top' 或 'ruleset'）
const editingProxy = ref(null);
const editingProxyName = ref(null);
const currentRule = ref({
  type: 'DOMAIN-SUFFIX',
  payload: '',
  action: 'DIRECT',
  additional_params: null,
  priority: 0
});

const newRuleProvider = ref({
  name: '',
  type: 'http',
  path: null,
  url: null,
  interval: 600,
  behavior: 'classical',
  format: 'yaml',
  'size-limit': 0,
  payload: [],
});

const newHost = ref({
  domain: '',
  value: [],
  using_cloudflare: false,
});

// 导入规则相关状态
const importRuleDialog = ref(false);
const importExtraProxiesDialog = ref(false);
const importRules = ref({
  type: 'YAML',
  payload: ''
});
const importExtraProxies = ref({
  type: 'YAML',
  payload: ''
});

// 排序后的规则
const sortedRules = computed(() => [...rules.value].sort((a, b) => a.priority - b.priority));
const sortedRulesetRules = computed(() => [...rulesetRules.value].sort((a, b) => a.priority - b.priority));
const ruleProviderNames = computed(() => {
  return extraRuleProviders.value.map(provider => provider.name)
});

const importExtraProxiesPlaceholderText = computed(() => {
  return importExtraProxies.value.type === 'YAML'
      ? 'proxies: []'
      : 'vless://xxxx';
});
const proxyGroupTypes = ref(['select', 'url-test', 'fallback', 'load-balance', 'smart']);

const strategyTypes = ref(['round-robin', 'consistent-hashing', 'sticky-sessions']);
const smartStrategyTypes = ref(['round-robin', 'sticky-sessions']);
const importRuleTypes = ['YAML'];
const importProxiesTypes = ['YAML', 'LINK'];
const ruleProviderTypes = ['http', 'file', 'inline'];
const ruleProviderBehaviorTypes = ['domain', 'ipcidr', 'classical'];
const ruleProviderFormatTypes = ['yaml', 'text', 'mrs'];
// 修改actions为计算属性，合并内置动作和自定义出站
const actions = computed(() => [
  'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE',
  ...customOutbounds.value.map(outbound => outbound.name)
]);

const proxyProviderNames = computed(() => Object.keys(proxyProviders.value));

const subscriptionsInfo = ref({});
const bestCloudflareIPs = ref([]);

// 自定义事件，用于通知主应用刷新数据
const emit = __emit;

function pageTitle(itemPerPageValue) {
  if (itemPerPageValue < 0) {
    return "♾️"
  }
  return `${itemPerPageValue}`
}

// 格式化字节为易读单位（如 1.5 GB）
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 在工具函数中添加时间戳转换
function formatTimestamp(timestamp) {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp * 1000); // 注意：JS时间戳是毫秒，需乘以1000
  return date.toLocaleDateString('zh-CN'); // 或使用其他格式如 date.toISOString().split('T')[0]
}

function timestampToDate(timestamp) {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp * 1000); // 注意：JS时间戳是毫秒，需乘以1000
  return date.toLocaleString('zh-CN', { // 'en-GB' 表示使用英国格式（YYYY-MM-DD HH:mm:ss）
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false // 24小时制
  });
}

// 更新过期时间颜色判断（基于时间戳）
function getExpireColor(timestamp) {
  if (!timestamp) return 'grey';
  const secondsLeft = timestamp - Math.floor(Date.now() / 1000);
  const daysLeft = secondsLeft / 86400;
  return daysLeft < 7 ? 'error' : daysLeft < 30 ? 'warning' : 'success';
}

// 复制功能
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    snackbar.value = {
      show: true,
      message: '已复制到剪贴板',
      color: 'success'
    };
  }).catch(() => {
    snackbar.value = {
      show: true,
      message: '复制失败',
      color: 'error'
    };
  });
}

// 计算已用流量百分比
function calculatePercentage(download, total) {
  return total > 0 ? Math.round((download / total) * 100) : 0;
}

// 根据流量百分比获取颜色
function getUsageColor(percentage) {
  return percentage > 90 ? 'error' : percentage > 70 ? 'warning' : 'success';
}

function getBehaviorColor(action) {
  const colors = {
    'classical': 'success',
    'domain': 'error',
    'ipcidr': 'error',
  };
  return colors[action] || 'primary'
}

function getActionColor(action) {
  const colors = {
    'DIRECT': 'success',
    'REJECT': 'error',
    'REJECT-DROP': 'error',
    'PASS': 'warning',
    'COMPATIBLE': 'info'
  };
  return colors[action] || 'primary'
}

function getProxyGroupTypeColor(action) {
  const colors = {
    'url-test': 'success',
    'fallback': 'error',
    'load-balance': 'primary',
    'select': 'info'
  };
  return colors[action] || 'warning'
}

function getProxyColor(action) {
  const colors = {
    'ss': 'success',
    'ssr': 'success',
    'trojan': 'error',
    'vmess': 'primary',
    'vless': 'primary',
    'hysteria': 'info',
    'hysteria2': 'info',
    'anytls': 'warning',
  };
  return colors[action] || 'secondary'
}

function getBoolColor(value) {
  if (value) {
    return 'primary'
  }
  return 'success'
}

function isSystemRule(rule) {
  return rule.remark?.startsWith('Auto');
}

function isManual(source) {
  return source === 'Manual';
}

function isInvalid(source) {
  return source === 'Invalid';
}

function isRegion(source) {
  return source === 'Region';
}

function isTemplate(source) {
  return source === 'Template';
}

function openImportRuleDialog() {
  importRules.value = {
    type: 'YAML',
    payload: ''
  };
  importRuleDialog.value = true;
}

function openImportExtraProxiesDialog() {
  importExtraProxies.value = {
    type: 'YAML',
    payload: ''
  };
  importExtraProxiesDialog.value = true;
}

// 打开添加规则对话框
function openAddRuleDialog(type = 'top') {
  editingPriority.value = null;
  editingType.value = type;
  const currentRules = type === 'top' ? sortedRules.value : sortedRulesetRules.value;
  const nextPriority = currentRules.length > 0
      ? Math.max(...currentRules.map(r => r.priority)) + 1
      : 0;
  currentRule.value = {
    type: 'DOMAIN-SUFFIX',
    payload: '',
    action: 'DIRECT',
    additional_params: null,
    priority: nextPriority
  };
  ruleDialogVisible.value = true;
}

function openAddRuleProviderDialog() {
  editingRuleProviderName.value = null;
  newRuleProvider.value = {
    name: '',
    type: 'http',
    path: null,
    url: null,
    interval: 600,
    behavior: 'classical',
    format: 'yaml',
    'size-limit': 0,
    payload: [],
  };
  ruleProviderDialog.value = true;
}

function openAddHostDialog() {
  editingHostDomainName.value = null;
  newHost.value = {
    domain: '',
    value: [],
    using_cloudflare: false,
  };
  hostDialog.value = true;
}

const showProxyGroupYaml = (proxyGroup) => {
  const proxyGroupCopy = {...proxyGroup};
  // 如果存在 source 键，删除它
  if ('source' in proxyGroupCopy) {
    delete proxyGroupCopy.source;
  }
  if ('v2ray_link' in proxyGroupCopy) {
    delete proxyGroupCopy.v2ray_link;
  }
  if ('overwritten' in proxyGroupCopy) {
    delete proxyGroupCopy.overwritten;
  }
  // 生成 YAML 并显示
  displayedYaml.value = jsYaml.dump(proxyGroupCopy);
  yamlDialog.value = true;
};

function openAddProxyGroupDialog() {
  editingProxyGroupName.value = null;
  newProxyGroup.value = {
    name: '',
    type: 'select',
    proxies: [],
    url: 'https://www.gstatic.com/generate_204',
    lazy: true,
    interval: 300,
    timeout: 5000,
    'disable-udp': false,
    filter: null,
    'include-all': false,
    'include-all-proxies': false,
    'include-all-providers': false,
    'exclude-filter': null,
    'expected-status': '*',
    'exclude-type': null,
    tolerance: null,
    strategy: null,
    hidden: false,
    icon: null,
    use: null,
    'max-failed-times': 5,
    'sample-rate': 1,
    'policy-priority': '1',
    uselightgbm: false,
    collectdata: false
  };
  proxyGroupDialog.value = true;
}

// 编辑规则
function editRule(priority, type = 'top') {
  editingType.value = type; // 记录当前编辑的类型
  const currentRules = type === 'top' ? sortedRules.value : sortedRulesetRules.value;
  const rule = currentRules.find(r => r.priority === priority);

  if (rule) {
    editingPriority.value = priority;
    currentRule.value = {
      type: rule.type,
      payload: rule?.payload,
      action: rule.action,
      additional_params: rule.additional_params || null,
      priority: rule.priority,
      conditions: rule?.conditions,
      condition: rule?.condition,
    };
    ruleDialogVisible.value = true;
  }
}

function openProxiesDialog(proxy) {
  editingProxyName.value = proxy.name;
  editingProxy.value = proxy;
  proxiesDialogVisible.value = true;
}

function editProxyGroup(name) {
  const proxyGroup = proxyGroups.value.find(p => p.name === name);
  if (proxyGroup) {
    editingProxyGroupName.value = name;
    newProxyGroup.value = {
      name: proxyGroup.name,
      type: proxyGroup.type,
      proxies: proxyGroup?.proxies || [],
      url: proxyGroup?.url || null,
      lazy: proxyGroup?.lazy ?? true,
      interval: proxyGroup?.interval ?? 300,
      timeout: proxyGroup?.timeout ?? 5000,
      'disable-udp': proxyGroup?.['disable-udp'] ?? false,
      filter: proxyGroup?.filter,
      'include-all': proxyGroup?.['include-all'] ?? false,
      'include-all-proxies': proxyGroup?.['include-all-proxies'] ?? false,
      'include-all-providers': proxyGroup?.['include-all-providers'] ?? false,
      'exclude-filter': proxyGroup?.['exclude-filter'] || null,
      'exclude-type': proxyGroup?.['exclude-type'] || null,
      tolerance: proxyGroup?.tolerance ?? null,
      strategy: proxyGroup?.strategy ?? null,
      'expected-status': proxyGroup?.['expected-status'] || '*',
      hidden: proxyGroup?.hidden ?? false,
      icon: proxyGroup?.icon || null,
      use: proxyGroup?.use || null,
      'max-failed-times': proxyGroup?.['max-failed-times'] ?? 5,
      'policy-priority': proxyGroup?.['policy-priority'] ?? '1',
      uselightgbm: proxyGroup?.['uselightgbm'] ?? false,
      collectdata: proxyGroup?.['collectdata'] ?? false,
      'sample-rate': proxyGroup?.['sample-rate'] ?? 1,
    };
    proxyGroupDialog.value = true;
  }
}

function editRuleProvider(name) {
  const ruleProvider = extraRuleProviders.value.find(r => r.name === name);
  if (ruleProvider) {
    editingRuleProviderName.value = name;
    newRuleProvider.value = {
      name: ruleProvider.name,
      type: ruleProvider.type,
      path: ruleProvider.path,
      url: ruleProvider.url,
      interval: ruleProvider.interval,
      behavior: ruleProvider.behavior,
      format: ruleProvider.format,
      'size-limit': ruleProvider['size-limit'],
      payload: ruleProvider.payload,
    };
    ruleProviderDialog.value = true;
  }
}

function editHost(domain) {
  const hostItem = hosts.value.find(r => r.domain === domain);
  if (hostItem) {
    editingHostDomainName.value = domain;
    newHost.value = {
      domain: hostItem.domain,
      value: hostItem.value,
      using_cloudflare: hostItem.using_cloudflare,
    };
    hostDialog.value = true;
  }
}

function showError(Msg) {
  error.value = true;
  errorMsg.value = Msg;
}

async function importRule() {
  try {
    importRuleLoading.value = true;
    const requestData = {
      type: importRules.value.type,
      payload: importRules.value.payload
    };
    const result = await props.api.post('/plugin/ClashRuleProvider/import', requestData);
    if (!result.success) {
      showError('规则导入失败: ' + (result.message || '未知错误'));
      snackbar.value = {
        show: true,
        message: '规则导入失败',
        color: 'error'
      };
      return
    }
    importRuleDialog.value = false;
    await refreshAllRegions(["top"]);
    // 显示成功提示
    snackbar.value = {
      show: true,
      message: '规则导入成功',
      color: 'success'
    };
  } catch (err) {
    showError('导入规则失败: ' + (err.message || '未知错误'));
    snackbar.value = {
      show: true,
      message: '导入规则失败',
      color: 'error'
    };
  } finally {
    importRuleLoading.value = false;
  }
}

async function importExtraProxiesFun() {
  try {
    importProxiesLoading.value = true;
    const requestData = {
      type: importExtraProxies.value.type,
      payload: importExtraProxies.value.payload
    };
    const result = await props.api.put('/plugin/ClashRuleProvider/proxies', requestData);
    if (!result.success) {
      showError('节点导入失败: ' + (result.message || '未知错误'));
      snackbar.value = {
        show: true,
        message: '节点导入失败',
        color: 'error'
      };
      return
    }
    importExtraProxiesDialog.value = false;
    await refreshAllRegions(["proxies", "clash-outbounds"]);
    // 显示成功提示
    snackbar.value = {
      show: true,
      message: '节点导入成功',
      color: 'success'
    };
  } catch (err) {
    showError('节点导入失败: ' + (err.message || '未知错误'));
    snackbar.value = {
      show: true,
      message: '节点导入失败',
      color: 'error'
    };
  } finally {
    importProxiesLoading.value = false;
  }
}

async function saveProxyGroups() {
  const {valid} = await proxyGroupsForm.value.validate();
  const action = editingProxyGroupName.value === null ? '添加代理组' : '更新代理组';
  if (!valid) return;
  try {
    saveProxyGroupLoading.value = true;
    const requestData = newProxyGroup.value;
    const name = encodeURIComponent(editingProxyGroupName.value);
    const path = editingProxyGroupName.value === null ? '' : `/${name}`;
    const method = editingProxyGroupName.value === null ? 'post' : 'patch';
    const result = await props.api[method](`/plugin/ClashRuleProvider/proxy-groups${path}`, requestData);
    if (!result.success) {
      showError(action + '失败: ' + (result.message || '未知错误'));
      snackbar.value = {
        show: true,
        message: action + '失败',
        color: 'error'
      };
      return
    }
    proxyGroupDialog.value = false;
    await refreshAllRegions(["clash-outbounds", "proxy-groups"]);
    snackbar.value = {
      show: true,
      message: action + '成功',
      color: 'success'
    };
  } catch (err) {
    showError(action + '失败: ' + (err.message || '未知错误'));
    snackbar.value = {
      show: true,
      message: action + '失败',
      color: 'error'
    };
  } finally {
    saveProxyGroupLoading.value = false;
  }
}

const proxyGroupsForm = ref(null);
const ruleProvidersForm = ref(null);
const hostForm = ref(null);

function closeRuleDialog() {
  ruleDialogVisible.value = false;
}

// 保存规则
async function saveRule(newRule) {
  try {
    saveRuleLoading.value = true;
    if (newRule.payload) {
      newRule.payload = newRule.payload.trim();
    }
    const requestData =
        {
          ...newRule,
          additional_params: newRule.additional_params
              ? newRule.additional_params
              : null
        }
    ;
    const priority = editingPriority.value === null ? '' : `/${editingPriority.value}`;
    const method = editingPriority.value === null ? 'post' : 'patch';
    const result = await props.api[method](`/plugin/ClashRuleProvider/rules/${editingType.value}${priority}`, requestData);
    if (!result.success) {
      showError('保存规则失败: ' + (result.message || '未知错误'));
      snackbar.value = {
        show: true,
        message: '保存规则合失败',
        color: 'error'
      };
      return
    }
    closeRuleDialog();
    await refreshAllRegions(["top", "ruleset"]);
    // 显示成功提示
    snackbar.value = {
      show: true,
      message: editingPriority.value === null ? '规则添加成功' : '规则更新成功',
      color: 'success'
    };
  } catch (err) {
    showError('保存规则失败: ' + (err.message || '未知错误'));
    snackbar.value = {
      show: true,
      message: '保存规则失败',
      color: 'error'
    };
  } finally {
    saveRuleLoading.value = false;
  }
}

async function saveRuleProvider() {
  const {valid} = await ruleProvidersForm.value.validate();
  if (!valid) return;
  try {
    saveRuleProviderLoading.value = true;
    const name = encodeURIComponent(editingRuleProviderName.value === null ? newRuleProvider.value.name : editingRuleProviderName.value);
    const requestData = {
      name: newRuleProvider.value.name,
      rule_provider: newRuleProvider.value,
    };
    const result = await props.api.post(`/plugin/ClashRuleProvider/rule-providers/${name}`, requestData);
    if (!result.success) {
      showError('保存规则集合失败: ' + (result.message || '未知错误'));
      snackbar.value = {
        show: true,
        message: '保存规则集合失败',
        color: 'error'
      };
      return
    }
    ruleProviderDialog.value = false;
    await refreshAllRegions(["rule-providers"]);
    snackbar.value = {
      show: true,
      message: editingRuleProviderName.value === null ? '规则集合添加成功' : '规则集合更新成功',
      color: 'success'
    };
  } catch (err) {
    showError('保存规则集合失败: ' + (err.message || '未知错误'));
    snackbar.value = {
      show: true,
      message: '保存规则集合失败',
      color: 'error'
    };
  } finally {
    saveRuleProviderLoading.value = false;
  }
}

const saveProxy = async (proxy) => {
  saveProxyLoading.value = true;
  try {
    const requestData = proxy;
    const name = encodeURIComponent(editingProxyName.value);
    const result = await props.api.patch(`/plugin/ClashRuleProvider/proxies/${name}`, requestData);
    if (!result.success) {
      showError('保存出站代理失败: ' + (result.message || '未知错误'));
      snackbar.value = {
        show: true,
        message: '保存出站代理失败',
        color: 'error'
      };
      return
    }
    proxiesDialogVisible.value = false;
    await refreshAllRegions(["proxies"]);
    snackbar.value = {
      show: true,
      message: editingProxyName.value === null ? '出站代理添加成功' : '出站代理更新成功',
      color: 'success'
    };
  } catch (err) {
    showError('保存 Proxy 失败: ' + (err.message || '未知错误'));
    snackbar.value = {
      show: true,
      message: '保存代理失败',
      color: 'error'
    };
  } finally {
    saveProxyLoading.value = false;
  }
};

async function saveHost() {
  const {valid} = await hostForm.value.validate();
  if (!valid) return;
  try {
    saveHostLoading.value = true;
    newHost.value.domain = newHost.value.domain.trim();
    const requestData = {
      domain: editingHostDomainName.value === null ? newHost.value.domain : editingHostDomainName.value,
      value: newHost.value
    };
    const result = await props.api.post('/plugin/ClashRuleProvider/hosts', requestData);
    if (!result.success) {
      showError('保存 Host 失败: ' + (result.message || '未知错误'));
      snackbar.value = {
        show: true,
        message: '保存 Host 失败',
        color: 'error'
      };
      return
    }
    hostDialog.value = false;
    await refreshAllRegions(["hosts"]);
    snackbar.value = {
      show: true,
      message: editingHostDomainName.value === null ? 'Host 添加成功' : 'Host 更新成功',
      color: 'success'
    };
  } catch (err) {
    showError('保存 Host 失败: ' + (err.message || '未知错误'));
    snackbar.value = {
      show: true,
      message: '保存 Host 失败',
      color: 'error'
    };
  } finally {
    saveHostLoading.value = false;
  }
}

// 删除规则
async function deleteRule(priority, type = 'top') {
  try {
    await props.api.delete(`/plugin/ClashRuleProvider/rules/${type}/${priority}`);
    await refreshAllRegions(["top", "ruleset"]);
  } catch (err) {
    showError(err.message || '删除规则失败');
  } finally {
  }
}

async function deleteRuleProvider(name) {
  try {
    const n = encodeURIComponent(name);
    await props.api.delete(`/plugin/ClashRuleProvider/rule-providers/${n}`);
    await refreshAllRegions(["rule-providers"]);
  } catch (err) {
    showError(err.message || '删除规则集合失败');
  }
}

async function deleteHost(name) {
  try {
    await props.api.delete('/plugin/ClashRuleProvider/hosts', {
      domain: name
    });
    await refreshAllRegions(["hosts"]);
  } catch (err) {
    showError(err.message || '删除 host 失败');
  }
}

async function deleteProxyGroup(name) {
  try {
    const n = encodeURIComponent(name);
    await props.api.delete(`/plugin/ClashRuleProvider/proxy-groups/${n}`);
    await refreshAllRegions(["proxy-groups", "clash-outbounds"]);
  } catch (err) {
    showError(err.message || '删除规则失败');
  }
}

async function deleteExtraProxies(name) {
  try {
    await props.api.delete(`/plugin/ClashRuleProvider/proxies/${name}`);
    await refreshAllRegions(["proxies", "clash-outbounds"]);
  } catch (err) {
    showError(err.message || '删除规则失败');
  }
}

// 更新订阅
async function updateSubscription(url) {
  if (!url) {
    showError('请先输入订阅URL');
    return
  }

  refreshingSubscription.value[url] = true;
  try {
    await props.api.put('plugin/ClashRuleProvider/refresh', {
      url: url
    });
    // 显示成功提示
    snackbar.value = {
      show: true,
      message: '订阅更新成功',
      color: 'success'
    };
    await refreshAllRegions(["status", "clash-outbounds", "rule-providers", "proxy-groups", "proxies", "proxy-providers"]);
  } catch (err) {
    showError(err.message);
  } finally {
    refreshingSubscription.value[url] = false;
  }
}

async function toggleSubscription(url, enabled) {
  try {
    await props.api.post('plugin/ClashRuleProvider/subscription-info', {
      url: url,
      value: enabled,
      field: 'enabled'
    });
    // 显示成功提示
    snackbar.value = {
      show: true,
      message: '设置成功',
      color: 'success'
    };
    await refreshAllRegions(["status"]);
  } catch (err) {
    showError(err.message);
  } finally {
    refreshingSubscription.value[url] = false;
  }
}

function extractDomain(url) {
  try {
    const hostname = new URL(url).hostname;
    // 按点分割
    const parts = hostname.split('.');
    // 如果是 IPv4/IPv6，直接返回
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.includes(':')) {
      return hostname
    }
    // 只有一段的直接返回
    if (parts.length <= 2) {
      return hostname
    }
    // 返回最后两段（example.com）
    return parts.slice(-2).join('.')
  } catch {
    return url
  }
}

async function refreshStatus() {
  const state = await props.api.get('/plugin/ClashRuleProvider/status');
  // 处理状态请求的响应
  status.value = state?.data?.state ? 'running' : 'disabled';
  subUrl.value = state?.data?.sub_url || '';

  if (state?.data?.subscription_info) {
    subscriptionsInfo.value = {};
    refreshingSubscription.value = {};
    Object.keys(state.data.subscription_info).forEach(url => {
      const newSubInfo = {
        download: 0,
        upload: 0,
        total: 0,
        expire: 0,
        last_update: 0,
        used_percentage: 0,
        rule_size: 0,
        proxy_num: 0,
        enabled: false
      };
      Object.keys(state.data.subscription_info[url]).forEach(key => {
        if (key in newSubInfo) {
          newSubInfo[key] = state.data.subscription_info[url][key];
        }
      });
      newSubInfo.used_percentage = calculatePercentage(
          state.data.subscription_info[url]?.download || 0,
          state.data.subscription_info[url]?.total || 0
      );
      refreshingSubscription[url] = false;
      subscriptionsInfo.value[url] = newSubInfo;
    });
  }
  bestCloudflareIPs.value = state?.data?.best_cf_ip || [];
  rulesetPrefix.value = state?.data?.ruleset_prefix || '📂<=';
  geoRules.value = state?.data?.geoRules ?? geoRules.value;
}

async function refreshTopRules() {
  const response = await props.api.get('/plugin/ClashRuleProvider/rules/top');
  rules.value = response?.data.rules || [];
}

async function refreshRulesetRules() {
  const response = await props.api.get('/plugin/ClashRuleProvider/rules/ruleset');
  rulesetRules.value = response?.data.rules || [];
}

async function refreshOutbounds() {
  const outboundsResponse = await props.api.get('/plugin/ClashRuleProvider/clash-outbound');
  customOutbounds.value = outboundsResponse?.data.outbound || [];
}

async function refreshExtraRuleProviders() {
  const providersResponse = await props.api.get('/plugin/ClashRuleProvider/rule-providers');
  extraRuleProviders.value = providersResponse?.data || [];
}

async function refreshProxyGroups() {
  const proxyGroupsResponse = await props.api.get('/plugin/ClashRuleProvider/proxy-groups');
  proxyGroups.value = proxyGroupsResponse?.data.proxy_groups || [];
}

async function refreshExtraProxies() {
  const extraProxiesResponse = await props.api.get('/plugin/ClashRuleProvider/proxies');
  extraProxies.value = extraProxiesResponse?.data.proxies || [];
}

async function refreshHosts() {
  const hostsResponse = await props.api.get('/plugin/ClashRuleProvider/hosts');
  hosts.value = hostsResponse?.data.hosts || [];
}

async function refreshProxyProviders() {
  const proxyProvidersResponse = await props.api.get('/plugin/ClashRuleProvider/proxy-providers');
  proxyProviders.value = proxyProvidersResponse?.data.proxy_providers || {};
}

async function refreshDataOf(region) {
  switch (region) {
    case "status":
      return refreshStatus();
    case "top":
      return refreshTopRules();
    case "ruleset":
      return refreshRulesetRules();
    case "clash-outbounds":
      return refreshOutbounds();
    case "rule-providers":
      return refreshExtraRuleProviders();
    case "proxy-groups":
      return refreshProxyGroups();
    case "proxies":
      return refreshExtraProxies();
    case "hosts":
      return refreshHosts();
    case "proxy-providers":
      return refreshProxyProviders();
    default:
      throw new Error("Unknown region: " + region);
  }
}

async function refreshAllRegions(regions) {
  try {
    await Promise.all(regions.map(refreshDataOf));
  } catch (err) {
    console.error('获取数据失败:', err);
    showError(err.message || '获取数据失败');
    status.value = 'error';
  } finally {
    lastUpdated.value = new Date().toLocaleString();
  }
}

// 获取和刷新数据
async function refreshData() {
  loading.value = true;
  error.value = false;
  errorMsg.value = '';
  try {
    // 并发发送所有独立的请求
    const [
      state,
      response,
      response_ruleset,
      outboundsResponse,
      providersResponse,
      proxyGroupsResponse,
      extraProxiesResponse,
      hostsResponse,
      proxyProvidersResponse,
    ] = await Promise.all([
      props.api.get('/plugin/ClashRuleProvider/status'),
      props.api.get('/plugin/ClashRuleProvider/rules/top'),
      props.api.get('/plugin/ClashRuleProvider/rules/ruleset'),
      props.api.get('/plugin/ClashRuleProvider/clash-outbound'),
      props.api.get('/plugin/ClashRuleProvider/rule-providers'),
      props.api.get('/plugin/ClashRuleProvider/proxy-groups'),
      props.api.get('/plugin/ClashRuleProvider/proxies'),
      props.api.get('/plugin/ClashRuleProvider/hosts'),
      props.api.get('/plugin/ClashRuleProvider/proxy-providers'),
    ]);

    // 处理状态请求的响应
    status.value = state?.data?.state ? 'running' : 'disabled';
    subUrl.value = state?.data?.sub_url || '';

    if (state?.data?.subscription_info) {
      subscriptionsInfo.value = {};
      refreshingSubscription.value = {};
      Object.keys(state.data.subscription_info).forEach(url => {
        const newSubInfo = {
          download: 0,
          upload: 0,
          total: 0,
          expire: 0,
          last_update: 0,
          used_percentage: 0,
          rule_size: 0,
          proxy_num: 0,
          enabled: false
        };
        Object.keys(state.data.subscription_info[url]).forEach(key => {
          if (key in newSubInfo) {
            newSubInfo[key] = state.data.subscription_info[url][key];
          }
        });
        newSubInfo.used_percentage = calculatePercentage(
            state.data.subscription_info[url]?.download || 0,
            state.data.subscription_info[url]?.total || 0
        );
        refreshingSubscription[url] = false;
        subscriptionsInfo.value[url] = newSubInfo;
      });
    }
    bestCloudflareIPs.value = state?.data?.best_cf_ip || [];
    rulesetPrefix.value = state?.data?.ruleset_prefix || '';
    geoRules.value = state?.data?.geoRules ?? geoRules.value;
    rules.value = response?.data.rules || [];
    rulesetRules.value = response_ruleset?.data.rules || [];
    customOutbounds.value = outboundsResponse?.data.outbound || [];
    extraRuleProviders.value = providersResponse?.data || [];
    proxyGroups.value = proxyGroupsResponse?.data.proxy_groups || [];
    extraProxies.value = extraProxiesResponse?.data.proxies || [];
    hosts.value = hostsResponse?.data.hosts || [];
    proxyProviders.value = proxyProvidersResponse?.data.proxy_providers || {};
    lastUpdated.value = new Date().toLocaleString();
  } catch (err) {
    console.error('获取数据失败:', err);
    showError(err.message || '获取数据失败');
    status.value = 'error';
  } finally {
    loading.value = false;
  }
}

// 通知主应用切换到配置页面
function notifySwitch() {
  emit('switch');
}

// 通知主应用关闭组件
function notifyClose() {
  emit('close');
}

// 组件挂载时加载数据
onMounted(() => {
  refreshData();
});


return (_ctx, _cache) => {
  const _component_v_alert = _resolveComponent("v-alert");
  const _component_v_icon = _resolveComponent("v-icon");
  const _component_v_chip = _resolveComponent("v-chip");
  const _component_v_card_title = _resolveComponent("v-card-title");
  const _component_v_btn = _resolveComponent("v-btn");
  const _component_v_card_item = _resolveComponent("v-card-item");
  const _component_v_skeleton_loader = _resolveComponent("v-skeleton-loader");
  const _component_v_tab = _resolveComponent("v-tab");
  const _component_v_tabs = _resolveComponent("v-tabs");
  const _component_v_text_field = _resolveComponent("v-text-field");
  const _component_v_col = _resolveComponent("v-col");
  const _component_v_row = _resolveComponent("v-row");
  const _component_v_data_table = _resolveComponent("v-data-table");
  const _component_v_card_text = _resolveComponent("v-card-text");
  const _component_v_divider = _resolveComponent("v-divider");
  const _component_v_spacer = _resolveComponent("v-spacer");
  const _component_v_card_actions = _resolveComponent("v-card-actions");
  const _component_v_card = _resolveComponent("v-card");
  const _component_v_pagination = _resolveComponent("v-pagination");
  const _component_v_list_item_title = _resolveComponent("v-list-item-title");
  const _component_v_list_item = _resolveComponent("v-list-item");
  const _component_v_list = _resolveComponent("v-list");
  const _component_v_menu = _resolveComponent("v-menu");
  const _component_v_window_item = _resolveComponent("v-window-item");
  const _component_v_tooltip = _resolveComponent("v-tooltip");
  const _component_v_card_action = _resolveComponent("v-card-action");
  const _component_v_progress_linear = _resolveComponent("v-progress-linear");
  const _component_v_switch = _resolveComponent("v-switch");
  const _component_v_window = _resolveComponent("v-window");
  const _component_v_expand_transition = _resolveComponent("v-expand-transition");
  const _component_v_snackbar = _resolveComponent("v-snackbar");
  const _component_v_select = _resolveComponent("v-select");
  const _component_v_form = _resolveComponent("v-form");
  const _component_v_dialog = _resolveComponent("v-dialog");
  const _component_v_textarea = _resolveComponent("v-textarea");
  const _component_v_combobox = _resolveComponent("v-combobox");

  return (_openBlock(), _createElementBlock("div", _hoisted_1, [
    _createVNode(_component_v_card, null, {
      default: _withCtx(() => [
        (error.value)
          ? (_openBlock(), _createBlock(_component_v_alert, {
              key: 0,
              modelValue: error.value,
              "onUpdate:modelValue": _cache[0] || (_cache[0] = $event => ((error).value = $event)),
              type: "error",
              class: "mb-4",
              closable: ""
            }, {
              default: _withCtx(() => [
                _createTextVNode(_toDisplayString(errorMsg.value), 1)
              ]),
              _: 1
            }, 8, ["modelValue"]))
          : _createCommentVNode("", true),
        _createVNode(_component_v_card_item, null, {
          append: _withCtx(() => [
            _createVNode(_component_v_btn, {
              icon: "",
              color: "primary",
              variant: "text",
              onClick: notifyClose
            }, {
              default: _withCtx(() => [
                _createVNode(_component_v_icon, { left: "" }, {
                  default: _withCtx(() => _cache[91] || (_cache[91] = [
                    _createTextVNode("mdi-close")
                  ])),
                  _: 1
                })
              ]),
              _: 1
            })
          ]),
          default: _withCtx(() => [
            _createVNode(_component_v_card_title, null, {
              default: _withCtx(() => [
                _createVNode(_component_v_icon, {
                  class: "mr-2",
                  size: "24"
                }, {
                  default: _withCtx(() => [
                    _createElementVNode("img", {
                      src: `/api/v1/system/img/1?cache=1&imgurl=${encodeURIComponent('https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/Meta.png')}`,
                      alt: "icon",
                      style: {"width":"100%","height":"100%"}
                    }, null, 8, _hoisted_2)
                  ]),
                  _: 1
                }),
                _cache[90] || (_cache[90] = _createTextVNode(" Clash Rule Provider ")),
                _createVNode(_component_v_chip, {
                  onClick: _cache[1] || (_cache[1] = $event => (copyToClipboard(subUrl.value))),
                  size: "small",
                  color: status.value === 'running' ? 'success' : 'warning'
                }, {
                  default: _withCtx(() => [
                    _createTextVNode(_toDisplayString(status.value), 1)
                  ]),
                  _: 1
                }, 8, ["color"])
              ]),
              _: 1
            })
          ]),
          _: 1
        }),
        _createVNode(_component_v_card_text, null, {
          default: _withCtx(() => [
            (loading.value)
              ? (_openBlock(), _createBlock(_component_v_skeleton_loader, {
                  key: 0,
                  type: "card"
                }))
              : (_openBlock(), _createElementBlock("div", _hoisted_3, [
                  _createVNode(_component_v_tabs, {
                    modelValue: activeTab.value,
                    "onUpdate:modelValue": _cache[2] || (_cache[2] = $event => ((activeTab).value = $event)),
                    "background-color": "primary",
                    dark: ""
                  }, {
                    default: _withCtx(() => [
                      _createVNode(_component_v_tab, null, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_icon, { start: "" }, {
                            default: _withCtx(() => _cache[92] || (_cache[92] = [
                              _createTextVNode("mdi-format-list-bulleted")
                            ])),
                            _: 1
                          }),
                          _cache[93] || (_cache[93] = _createTextVNode(" 规则集规则 "))
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_tab, null, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_icon, { start: "" }, {
                            default: _withCtx(() => _cache[94] || (_cache[94] = [
                              _createTextVNode("mdi-pin")
                            ])),
                            _: 1
                          }),
                          _cache[95] || (_cache[95] = _createTextVNode(" 置顶规则 "))
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_tab, null, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_icon, { start: "" }, {
                            default: _withCtx(() => _cache[96] || (_cache[96] = [
                              _createTextVNode("mdi-source-branch")
                            ])),
                            _: 1
                          }),
                          _cache[97] || (_cache[97] = _createTextVNode(" 代理组 "))
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_tab, null, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_icon, { start: "" }, {
                            default: _withCtx(() => _cache[98] || (_cache[98] = [
                              _createTextVNode("mdi-rocket-launch")
                            ])),
                            _: 1
                          }),
                          _cache[99] || (_cache[99] = _createTextVNode(" 出站代理 "))
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_tab, null, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_icon, { start: "" }, {
                            default: _withCtx(() => _cache[100] || (_cache[100] = [
                              _createTextVNode("mdi-folder-multiple")
                            ])),
                            _: 1
                          }),
                          _cache[101] || (_cache[101] = _createTextVNode(" 规则集合 "))
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_tab, null, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_icon, { start: "" }, {
                            default: _withCtx(() => _cache[102] || (_cache[102] = [
                              _createTextVNode("mdi-lan")
                            ])),
                            _: 1
                          }),
                          _cache[103] || (_cache[103] = _createTextVNode(" Hosts "))
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_tab, null, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_icon, { start: "" }, {
                            default: _withCtx(() => _cache[104] || (_cache[104] = [
                              _createTextVNode("mdi-cloud-sync")
                            ])),
                            _: 1
                          }),
                          _cache[105] || (_cache[105] = _createTextVNode(" 订阅状态 "))
                        ]),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"]),
                  _createVNode(_component_v_window, {
                    modelValue: activeTab.value,
                    "onUpdate:modelValue": _cache[29] || (_cache[29] = $event => ((activeTab).value = $event))
                  }, {
                    default: _withCtx(() => [
                      _createVNode(_component_v_window_item, null, {
                        default: _withCtx(() => [
                          _createElementVNode("div", _hoisted_4, [
                            _createElementVNode("div", _hoisted_5, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "10",
                                    sm: "6",
                                    class: "d-flex justify-start"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_text_field, {
                                        modelValue: searchRulesetRule.value,
                                        "onUpdate:modelValue": _cache[3] || (_cache[3] = $event => ((searchRulesetRule).value = $event)),
                                        label: "搜索规则",
                                        clearable: "",
                                        density: "compact",
                                        variant: "solo-filled",
                                        "hide-details": "",
                                        class: "search-field",
                                        "prepend-inner-icon": "mdi-magnify",
                                        flat: "",
                                        rounded: "pill",
                                        "single-line": ""
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    sm: "6",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_btn, {
                                        color: "primary",
                                        onClick: _cache[4] || (_cache[4] = $event => (openAddRuleDialog('ruleset'))),
                                        icon: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[106] || (_cache[106] = [
                                              _createTextVNode("mdi-plus")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_6, [
                              (_openBlock(), _createBlock(_component_v_data_table, {
                                "fixed-header": "",
                                class: "px-4",
                                headers: headersRuleset.value,
                                items: sortedRulesetRules.value,
                                search: searchRulesetRule.value,
                                page: pageRuleset.value,
                                "onUpdate:page": _cache[5] || (_cache[5] = $event => ((pageRuleset).value = $event)),
                                "items-per-page": itemsPerPageRuleset.value,
                                "items-per-page-options": itemsPerPageOptions.value,
                                "item-key": "priority",
                                density: "compact",
                                "hide-default-footer": "",
                                key: pageRuleset.value
                              }, {
                                item: _withCtx(({ item }) => [
                                  _createElementVNode("tr", {
                                    class: _normalizeClass({ 'bg-blue-lighten-5': item._isHovered }),
                                    draggable: "true",
                                    onDragstart: $event => (dragStart($event, item.priority, 'ruleset')),
                                    onDragover: _withModifiers($event => (dragOver($event, item.priority, 'ruleset')), ["prevent"]),
                                    onDrop: $event => (drop($event, item.priority, 'ruleset'))
                                  }, [
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_icon, { class: "drag-handle mr-1" }, {
                                        default: _withCtx(() => _cache[107] || (_cache[107] = [
                                          _createTextVNode("mdi-drag")
                                        ])),
                                        _: 1
                                      }),
                                      _createTextVNode(" " + _toDisplayString(item.priority), 1)
                                    ]),
                                    _createElementVNode("td", null, _toDisplayString(item.type), 1),
                                    _createElementVNode("td", null, _toDisplayString(item.payload), 1),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_chip, {
                                        color: getActionColor(item.action),
                                        size: "small",
                                        label: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createTextVNode(_toDisplayString(item.action), 1)
                                        ]),
                                        _: 2
                                      }, 1032, ["color"])
                                    ]),
                                    _createElementVNode("td", null, _toDisplayString(rulesetPrefix.value) + _toDisplayString(item.action), 1),
                                    (item?.time_modified)
                                      ? (_openBlock(), _createElementBlock("td", _hoisted_8, _toDisplayString(timestampToDate(item.time_modified)), 1))
                                      : (_openBlock(), _createElementBlock("td", _hoisted_9)),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "primary",
                                        variant: "text",
                                        onClick: $event => (editRule(item.priority, 'ruleset'))
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[108] || (_cache[108] = [
                                              _createTextVNode("mdi-pencil")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick"]),
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "error",
                                        variant: "text",
                                        onClick: $event => (deleteRule(item.priority, 'ruleset'))
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[109] || (_cache[109] = [
                                              _createTextVNode("mdi-delete")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick"])
                                    ])
                                  ], 42, _hoisted_7)
                                ]),
                                _: 1
                              }, 8, ["headers", "items", "search", "page", "items-per-page", "items-per-page-options"]))
                            ]),
                            _createElementVNode("div", _hoisted_10, [
                              _createVNode(_component_v_row, null, {
                                default: _withCtx(() => [
                                  (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(paginatedRulesetRules.value, (item) => {
                                    return (_openBlock(), _createBlock(_component_v_col, {
                                      key: item.priority,
                                      cols: "12"
                                    }, {
                                      default: _withCtx(() => [
                                        _createVNode(_component_v_card, {
                                          rounded: "lg",
                                          elevation: "1"
                                        }, {
                                          default: _withCtx(() => [
                                            _createVNode(_component_v_card_title, { class: "d-flex justify-space-between align-center" }, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", null, [
                                                  _createVNode(_component_v_icon, {
                                                    small: "",
                                                    class: "mr-1"
                                                  }, {
                                                    default: _withCtx(() => _cache[110] || (_cache[110] = [
                                                      _createTextVNode("mdi-order-numeric-ascending")
                                                    ])),
                                                    _: 1
                                                  }),
                                                  _createElementVNode("span", _hoisted_11, "优先级 " + _toDisplayString(item.priority), 1)
                                                ]),
                                                _createVNode(_component_v_chip, {
                                                  color: getActionColor(item.action),
                                                  size: "small",
                                                  label: ""
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createTextVNode(_toDisplayString(item.action), 1)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["color"])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_card_text, null, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", _hoisted_12, [
                                                  _cache[111] || (_cache[111] = _createElementVNode("strong", null, "类型：", -1)),
                                                  _createTextVNode(_toDisplayString(item.type), 1)
                                                ]),
                                                _createElementVNode("div", _hoisted_13, [
                                                  _cache[112] || (_cache[112] = _createElementVNode("strong", null, "内容：", -1)),
                                                  _createTextVNode(_toDisplayString(item.payload), 1)
                                                ]),
                                                _createElementVNode("div", _hoisted_14, [
                                                  _cache[113] || (_cache[113] = _createElementVNode("strong", null, "规则：", -1)),
                                                  _createTextVNode(_toDisplayString(rulesetPrefix.value) + _toDisplayString(item.action), 1)
                                                ])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_divider),
                                            _createVNode(_component_v_card_actions, { class: "d-flex justify-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  color: "primary",
                                                  size: "small",
                                                  onClick: $event => (editRule(item.priority, 'ruleset'))
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[114] || (_cache[114] = [
                                                        _createTextVNode("mdi-pencil")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick"]),
                                                _createVNode(_component_v_spacer),
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  color: "error",
                                                  size: "small",
                                                  onClick: $event => (deleteRule(item.priority, 'ruleset'))
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[115] || (_cache[115] = [
                                                        _createTextVNode("mdi-delete")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick"])
                                              ]),
                                              _: 2
                                            }, 1024)
                                          ]),
                                          _: 2
                                        }, 1024)
                                      ]),
                                      _: 2
                                    }, 1024))
                                  }), 128))
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_15, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1"
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "8",
                                    md: "10",
                                    class: "d-flex justify-center"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageRuleset.value,
                                        "onUpdate:modelValue": _cache[6] || (_cache[6] = $event => ((pageRuleset).value = $event)),
                                        length: pageCountRuleset.value,
                                        "total-visible": "5",
                                        rounded: "circle",
                                        class: "d-none d-sm-flex my-0"
                                      }, null, 8, ["modelValue", "length"]),
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageRuleset.value,
                                        "onUpdate:modelValue": _cache[7] || (_cache[7] = $event => ((pageRuleset).value = $event)),
                                        length: pageCountRuleset.value,
                                        "total-visible": "0",
                                        rounded: "circle",
                                        class: "d-sm-none my-0"
                                      }, null, 8, ["modelValue", "length"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_menu, null, {
                                        activator: _withCtx(({ props }) => [
                                          _createVNode(_component_v_btn, _mergeProps(props, {
                                            icon: "",
                                            rounded: "circle",
                                            variant: "tonal"
                                          }), {
                                            default: _withCtx(() => [
                                              _createTextVNode(_toDisplayString(pageTitle(itemsPerPageRuleset.value)), 1)
                                            ]),
                                            _: 2
                                          }, 1040)
                                        ]),
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_list, null, {
                                            default: _withCtx(() => [
                                              (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(itemsPerPageOptions.value, (item, index) => {
                                                return (_openBlock(), _createBlock(_component_v_list_item, {
                                                  key: index,
                                                  value: item.value,
                                                  onClick: $event => (itemsPerPageRuleset.value = item.value)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_list_item_title, null, {
                                                      default: _withCtx(() => [
                                                        _createTextVNode(_toDisplayString(item.title), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["value", "onClick"]))
                                              }), 128))
                                            ]),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createVNode(_component_v_divider),
                            _cache[116] || (_cache[116] = _createElementVNode("div", { class: "text-caption text-grey mt-2" }, " * 对规则集的修改会在 Clash 中立即生效。 ", -1))
                          ])
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_window_item, null, {
                        default: _withCtx(() => [
                          _createElementVNode("div", _hoisted_16, [
                            _createElementVNode("div", _hoisted_17, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "8",
                                    sm: "6",
                                    class: "d-flex justify-start"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_text_field, {
                                        modelValue: searchTopRule.value,
                                        "onUpdate:modelValue": _cache[8] || (_cache[8] = $event => ((searchTopRule).value = $event)),
                                        label: "搜索规则",
                                        clearable: "",
                                        density: "compact",
                                        variant: "solo-filled",
                                        "hide-details": "",
                                        class: "search-field",
                                        "prepend-inner-icon": "mdi-magnify",
                                        flat: "",
                                        rounded: "pill",
                                        "single-line": ""
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "4",
                                    sm: "6",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_btn, {
                                        color: "secondary",
                                        onClick: openImportRuleDialog,
                                        icon: "",
                                        class: "mr-2"
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[117] || (_cache[117] = [
                                              _createTextVNode("mdi-import")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      }),
                                      _createVNode(_component_v_btn, {
                                        color: "primary",
                                        onClick: _cache[9] || (_cache[9] = $event => (openAddRuleDialog('top'))),
                                        icon: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[118] || (_cache[118] = [
                                              _createTextVNode("mdi-plus")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_18, [
                              _createVNode(_component_v_data_table, {
                                class: "px-4",
                                headers: headers.value,
                                search: searchTopRule.value,
                                items: sortedRules.value,
                                page: page.value,
                                "onUpdate:page": _cache[10] || (_cache[10] = $event => ((page).value = $event)),
                                "items-per-page": itemsPerPage.value,
                                "items-per-page-options": itemsPerPageOptions.value,
                                "item-key": "priority",
                                density: "compact",
                                "hide-default-footer": "",
                                "fixed-header": ""
                              }, {
                                item: _withCtx(({ item, index }) => [
                                  _createElementVNode("tr", {
                                    class: _normalizeClass({ 'bg-blue-lighten-5': item._isHovered }),
                                    draggable: "true",
                                    onDragstart: $event => (dragStart($event, item.priority, 'top')),
                                    onDragover: _withModifiers($event => (dragOver($event, item.priority, 'top')), ["prevent"]),
                                    onDrop: $event => (drop($event, item.priority, 'top'))
                                  }, [
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_icon, { class: "drag-handle" }, {
                                        default: _withCtx(() => _cache[119] || (_cache[119] = [
                                          _createTextVNode("mdi-drag")
                                        ])),
                                        _: 1
                                      }),
                                      _createTextVNode(" " + _toDisplayString(item.priority), 1)
                                    ]),
                                    _createElementVNode("td", null, _toDisplayString(item.type), 1),
                                    _createElementVNode("td", null, _toDisplayString(item.payload), 1),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_chip, {
                                        color: getActionColor(item.action),
                                        size: "small",
                                        label: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createTextVNode(_toDisplayString(item.action), 1)
                                        ]),
                                        _: 2
                                      }, 1032, ["color"])
                                    ]),
                                    (item?.time_modified)
                                      ? (_openBlock(), _createElementBlock("td", _hoisted_20, _toDisplayString(timestampToDate(item.time_modified)), 1))
                                      : (_openBlock(), _createElementBlock("td", _hoisted_21)),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "primary",
                                        variant: "text",
                                        onClick: $event => (editRule(item.priority, 'top')),
                                        disabled: isSystemRule(item)
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[120] || (_cache[120] = [
                                              _createTextVNode("mdi-pencil")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick", "disabled"]),
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "error",
                                        variant: "text",
                                        onClick: $event => (deleteRule(item.priority, 'top')),
                                        disabled: isSystemRule(item)
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[121] || (_cache[121] = [
                                              _createTextVNode("mdi-delete")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick", "disabled"]),
                                      (isSystemRule(item))
                                        ? (_openBlock(), _createBlock(_component_v_tooltip, {
                                            key: 0,
                                            activator: "parent",
                                            location: "top"
                                          }, {
                                            default: _withCtx(() => _cache[122] || (_cache[122] = [
                                              _createTextVNode(" 根据规则集自动添加 ")
                                            ])),
                                            _: 1
                                          }))
                                        : _createCommentVNode("", true)
                                    ])
                                  ], 42, _hoisted_19)
                                ]),
                                _: 1
                              }, 8, ["headers", "search", "items", "page", "items-per-page", "items-per-page-options"])
                            ]),
                            _createElementVNode("div", _hoisted_22, [
                              _createVNode(_component_v_row, null, {
                                default: _withCtx(() => [
                                  (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(paginatedTopRules.value, (item) => {
                                    return (_openBlock(), _createBlock(_component_v_col, {
                                      key: item.priority,
                                      cols: "12"
                                    }, {
                                      default: _withCtx(() => [
                                        _createVNode(_component_v_card, {
                                          rounded: "lg",
                                          elevation: "1"
                                        }, {
                                          default: _withCtx(() => [
                                            _createVNode(_component_v_card_title, { class: "d-flex justify-space-between align-center" }, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", null, [
                                                  _createVNode(_component_v_icon, {
                                                    small: "",
                                                    class: "mr-1"
                                                  }, {
                                                    default: _withCtx(() => _cache[123] || (_cache[123] = [
                                                      _createTextVNode("mdi-order-numeric-ascending")
                                                    ])),
                                                    _: 1
                                                  }),
                                                  _createElementVNode("span", _hoisted_23, "优先级 " + _toDisplayString(item.priority), 1)
                                                ]),
                                                _createVNode(_component_v_chip, {
                                                  color: getActionColor(item.action),
                                                  size: "small",
                                                  label: ""
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createTextVNode(_toDisplayString(item.action), 1)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["color"])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_card_text, null, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", _hoisted_24, [
                                                  _cache[124] || (_cache[124] = _createElementVNode("strong", null, "类型：", -1)),
                                                  _createTextVNode(_toDisplayString(item.type), 1)
                                                ]),
                                                _createElementVNode("div", _hoisted_25, [
                                                  _cache[125] || (_cache[125] = _createElementVNode("strong", null, "内容：", -1)),
                                                  _createTextVNode(_toDisplayString(item.payload), 1)
                                                ])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_divider),
                                            _createVNode(_component_v_card_actions, { class: "d-flex justify-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  color: "primary",
                                                  size: "small",
                                                  disabled: isSystemRule(item),
                                                  onClick: $event => (editRule(item.priority, 'top'))
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[126] || (_cache[126] = [
                                                        _createTextVNode("mdi-pencil")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["disabled", "onClick"]),
                                                _createVNode(_component_v_spacer),
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  color: "error",
                                                  size: "small",
                                                  onClick: $event => (deleteRule(item.priority, 'top')),
                                                  disabled: isSystemRule(item)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[127] || (_cache[127] = [
                                                        _createTextVNode("mdi-delete")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick", "disabled"])
                                              ]),
                                              _: 2
                                            }, 1024)
                                          ]),
                                          _: 2
                                        }, 1024)
                                      ]),
                                      _: 2
                                    }, 1024))
                                  }), 128))
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_26, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1"
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "8",
                                    md: "10",
                                    class: "d-flex justify-center"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_pagination, {
                                        modelValue: page.value,
                                        "onUpdate:modelValue": _cache[11] || (_cache[11] = $event => ((page).value = $event)),
                                        length: pageCount.value,
                                        "total-visible": "5",
                                        rounded: "circle",
                                        class: "d-none d-sm-flex my-0"
                                      }, null, 8, ["modelValue", "length"]),
                                      _createVNode(_component_v_pagination, {
                                        modelValue: page.value,
                                        "onUpdate:modelValue": _cache[12] || (_cache[12] = $event => ((page).value = $event)),
                                        length: pageCount.value,
                                        "total-visible": "0",
                                        rounded: "circle",
                                        class: "d-sm-none my-0"
                                      }, null, 8, ["modelValue", "length"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_menu, null, {
                                        activator: _withCtx(({ props }) => [
                                          _createVNode(_component_v_btn, _mergeProps(props, {
                                            icon: "",
                                            rounded: "circle",
                                            variant: "tonal"
                                          }), {
                                            default: _withCtx(() => [
                                              _createTextVNode(_toDisplayString(pageTitle(itemsPerPage.value)), 1)
                                            ]),
                                            _: 2
                                          }, 1040)
                                        ]),
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_list, null, {
                                            default: _withCtx(() => [
                                              (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(itemsPerPageOptions.value, (item, index) => {
                                                return (_openBlock(), _createBlock(_component_v_list_item, {
                                                  key: index,
                                                  value: item.value,
                                                  onClick: $event => (itemsPerPage.value = item.value)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_list_item_title, null, {
                                                      default: _withCtx(() => [
                                                        _createTextVNode(_toDisplayString(item.title), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["value", "onClick"]))
                                              }), 128))
                                            ]),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createVNode(_component_v_divider),
                            _cache[128] || (_cache[128] = _createElementVNode("div", { class: "text-caption text-grey mt-2" }, " *置顶规则用于管理来自规则集的匹配规则，这些规则会动态更新。 ", -1)),
                            _cache[129] || (_cache[129] = _createElementVNode("div", { class: "text-caption text-grey mt-2" }, " *对置顶规则的修改只有Clash更新配置后才会生效。 ", -1))
                          ])
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_window_item, null, {
                        default: _withCtx(() => [
                          _createElementVNode("div", _hoisted_27, [
                            _createElementVNode("div", _hoisted_28, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "10",
                                    sm: "6",
                                    class: "d-flex justify-start"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_text_field, {
                                        modelValue: searchProxyGroups.value,
                                        "onUpdate:modelValue": _cache[13] || (_cache[13] = $event => ((searchProxyGroups).value = $event)),
                                        label: "搜索代理组",
                                        clearable: "",
                                        density: "compact",
                                        variant: "solo-filled",
                                        "hide-details": "",
                                        class: "search-field",
                                        "prepend-inner-icon": "mdi-magnify",
                                        flat: "",
                                        rounded: "pill",
                                        "single-line": ""
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    sm: "6",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_btn, {
                                        color: "primary",
                                        onClick: openAddProxyGroupDialog,
                                        icon: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[130] || (_cache[130] = [
                                              _createTextVNode("mdi-plus")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_29, [
                              _createVNode(_component_v_data_table, {
                                class: "px-4",
                                headers: proxyGroupHeaders.value,
                                search: searchProxyGroups.value,
                                items: proxyGroups.value,
                                page: pageProxyGroup.value,
                                "onUpdate:page": _cache[14] || (_cache[14] = $event => ((pageProxyGroup).value = $event)),
                                "items-per-page": itemsPerPageProxyGroup.value,
                                "items-per-page-options": itemsPerPageOptions.value,
                                density: "compact",
                                "hide-default-footer": "",
                                "fixed-header": "",
                                "item-key": "name"
                              }, {
                                item: _withCtx(({ item, index }) => [
                                  _createElementVNode("tr", null, [
                                    _createElementVNode("td", null, _toDisplayString(item.name), 1),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_chip, {
                                        color: getProxyGroupTypeColor(item.type),
                                        size: "small",
                                        label: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createTextVNode(_toDisplayString(item.type), 1)
                                        ]),
                                        _: 2
                                      }, 1032, ["color"])
                                    ]),
                                    _createElementVNode("td", null, [
                                      (isManual(item.source))
                                        ? (_openBlock(), _createBlock(_component_v_icon, {
                                            key: 0,
                                            color: "primary"
                                          }, {
                                            default: _withCtx(() => _cache[131] || (_cache[131] = [
                                              _createTextVNode("mdi-feather")
                                            ])),
                                            _: 1
                                          }))
                                        : (isRegion(item.source))
                                          ? (_openBlock(), _createBlock(_component_v_icon, {
                                              key: 1,
                                              color: "info"
                                            }, {
                                              default: _withCtx(() => _cache[132] || (_cache[132] = [
                                                _createTextVNode("mdi-earth")
                                              ])),
                                              _: 1
                                            }))
                                          : (isTemplate(item.source))
                                            ? (_openBlock(), _createBlock(_component_v_icon, {
                                                key: 2,
                                                color: "success"
                                              }, {
                                                default: _withCtx(() => _cache[133] || (_cache[133] = [
                                                  _createTextVNode("mdi-file-code-outline")
                                                ])),
                                                _: 1
                                              }))
                                            : (_openBlock(), _createBlock(_component_v_chip, {
                                                key: 3,
                                                size: "small",
                                                label: ""
                                              }, {
                                                default: _withCtx(() => _cache[134] || (_cache[134] = [
                                                  _createTextVNode("item.source")
                                                ])),
                                                _: 1
                                              }))
                                    ]),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "info",
                                        variant: "text",
                                        onClick: $event => (showProxyGroupYaml(item))
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[135] || (_cache[135] = [
                                              _createTextVNode("mdi-code-json")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick"]),
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "primary",
                                        variant: "text",
                                        onClick: $event => (editProxyGroup(item.name)),
                                        disabled: !(isManual(item.source)||isRegion(item.source))
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[136] || (_cache[136] = [
                                              _createTextVNode("mdi-pencil")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick", "disabled"]),
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "error",
                                        variant: "text",
                                        onClick: $event => (deleteProxyGroup(item.name)),
                                        disabled: !isManual(item.source)
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[137] || (_cache[137] = [
                                              _createTextVNode("mdi-delete")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick", "disabled"])
                                    ])
                                  ])
                                ]),
                                _: 1
                              }, 8, ["headers", "search", "items", "page", "items-per-page", "items-per-page-options"])
                            ]),
                            _createElementVNode("div", _hoisted_30, [
                              _createVNode(_component_v_row, null, {
                                default: _withCtx(() => [
                                  (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(paginatedProxyGroups.value, (item) => {
                                    return (_openBlock(), _createBlock(_component_v_col, {
                                      key: item.name,
                                      cols: "12"
                                    }, {
                                      default: _withCtx(() => [
                                        _createVNode(_component_v_card, {
                                          rounded: "lg",
                                          elevation: "1"
                                        }, {
                                          default: _withCtx(() => [
                                            _createVNode(_component_v_card_title, { class: "d-flex justify-space-between align-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_row, { align: "center" }, {
                                                  default: _withCtx(() => [
                                                    (isManual(item.source))
                                                      ? (_openBlock(), _createBlock(_component_v_icon, {
                                                          key: 0,
                                                          start: "",
                                                          size: "x-small",
                                                          color: "primary"
                                                        }, {
                                                          default: _withCtx(() => _cache[138] || (_cache[138] = [
                                                            _createTextVNode("mdi-feather")
                                                          ])),
                                                          _: 1
                                                        }))
                                                      : (isRegion(item.source))
                                                        ? (_openBlock(), _createBlock(_component_v_icon, {
                                                            key: 1,
                                                            start: "",
                                                            size: "x-small",
                                                            color: "info"
                                                          }, {
                                                            default: _withCtx(() => _cache[139] || (_cache[139] = [
                                                              _createTextVNode("mdi-earth")
                                                            ])),
                                                            _: 1
                                                          }))
                                                        : (isTemplate(item.source))
                                                          ? (_openBlock(), _createBlock(_component_v_icon, {
                                                              key: 2,
                                                              start: "",
                                                              size: "x-small",
                                                              color: "success"
                                                            }, {
                                                              default: _withCtx(() => _cache[140] || (_cache[140] = [
                                                                _createTextVNode("mdi-file-code-outline")
                                                              ])),
                                                              _: 1
                                                            }))
                                                          : (_openBlock(), _createBlock(_component_v_chip, {
                                                              key: 3,
                                                              size: "small",
                                                              label: ""
                                                            }, {
                                                              default: _withCtx(() => _cache[141] || (_cache[141] = [
                                                                _createTextVNode("item.source")
                                                              ])),
                                                              _: 1
                                                            })),
                                                    _createElementVNode("span", _hoisted_31, _toDisplayString(item.name), 1)
                                                  ]),
                                                  _: 2
                                                }, 1024),
                                                _createVNode(_component_v_chip, {
                                                  color: getProxyGroupTypeColor(item.type),
                                                  size: "small",
                                                  label: ""
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createTextVNode(_toDisplayString(item.type), 1)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["color"])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_card_text, null, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", _hoisted_32, [
                                                  _cache[142] || (_cache[142] = _createElementVNode("strong", null, "类型：", -1)),
                                                  _createTextVNode(_toDisplayString(item.type), 1)
                                                ])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_divider),
                                            _createVNode(_component_v_card_actions, { class: "d-flex justify-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "primary",
                                                  variant: "text",
                                                  onClick: $event => (editProxyGroup(item.name)),
                                                  disabled: !(isManual(item.source)||isRegion(item.source))
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[143] || (_cache[143] = [
                                                        _createTextVNode("mdi-pencil")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick", "disabled"]),
                                                _createVNode(_component_v_spacer),
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "info",
                                                  variant: "text",
                                                  onClick: $event => (showProxyGroupYaml(item))
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[144] || (_cache[144] = [
                                                        _createTextVNode("mdi-code-json")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick"]),
                                                _createVNode(_component_v_spacer),
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "error",
                                                  variant: "text",
                                                  onClick: $event => (deleteProxyGroup(item.name)),
                                                  disabled: !isManual(item.source)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[145] || (_cache[145] = [
                                                        _createTextVNode("mdi-delete")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick", "disabled"])
                                              ]),
                                              _: 2
                                            }, 1024)
                                          ]),
                                          _: 2
                                        }, 1024)
                                      ]),
                                      _: 2
                                    }, 1024))
                                  }), 128))
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_33, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1"
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "8",
                                    md: "10",
                                    class: "d-flex justify-center"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageProxyGroup.value,
                                        "onUpdate:modelValue": _cache[15] || (_cache[15] = $event => ((pageProxyGroup).value = $event)),
                                        length: pageCountProxyGroups.value,
                                        "total-visible": "5",
                                        class: "d-none d-sm-flex my-0",
                                        rounded: "circle"
                                      }, null, 8, ["modelValue", "length"]),
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageProxyGroup.value,
                                        "onUpdate:modelValue": _cache[16] || (_cache[16] = $event => ((pageProxyGroup).value = $event)),
                                        length: pageCountProxyGroups.value,
                                        "total-visible": "0",
                                        class: "d-sm-none my-0",
                                        rounded: "circle"
                                      }, null, 8, ["modelValue", "length"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_menu, null, {
                                        activator: _withCtx(({ props }) => [
                                          _createVNode(_component_v_btn, _mergeProps(props, {
                                            icon: "",
                                            rounded: "circle",
                                            variant: "tonal"
                                          }), {
                                            default: _withCtx(() => [
                                              _createTextVNode(_toDisplayString(pageTitle(itemsPerPageProxyGroup.value)), 1)
                                            ]),
                                            _: 2
                                          }, 1040)
                                        ]),
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_list, null, {
                                            default: _withCtx(() => [
                                              (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(itemsPerPageOptions.value, (item, index) => {
                                                return (_openBlock(), _createBlock(_component_v_list_item, {
                                                  key: index,
                                                  value: item.value,
                                                  onClick: $event => (itemsPerPageProxyGroup.value = item.value)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_list_item_title, null, {
                                                      default: _withCtx(() => [
                                                        _createTextVNode(_toDisplayString(item.title), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["value", "onClick"]))
                                              }), 128))
                                            ]),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createVNode(_component_v_divider)
                          ])
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_window_item, null, {
                        default: _withCtx(() => [
                          _createElementVNode("div", _hoisted_34, [
                            _createElementVNode("div", _hoisted_35, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "10",
                                    sm: "6",
                                    class: "d-flex justify-start"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_text_field, {
                                        modelValue: searchExtraProxies.value,
                                        "onUpdate:modelValue": _cache[17] || (_cache[17] = $event => ((searchExtraProxies).value = $event)),
                                        label: "搜索出站代理",
                                        clearable: "",
                                        density: "compact",
                                        variant: "solo-filled",
                                        "hide-details": "",
                                        class: "search-field",
                                        "prepend-inner-icon": "mdi-magnify",
                                        flat: "",
                                        rounded: "pill",
                                        "single-line": ""
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    sm: "6",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_btn, {
                                        color: "primary",
                                        onClick: openImportExtraProxiesDialog,
                                        icon: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[146] || (_cache[146] = [
                                              _createTextVNode("mdi-import")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_36, [
                              _createVNode(_component_v_data_table, {
                                class: "px-4",
                                headers: extraProxiesHeaders.value,
                                search: searchExtraProxies.value,
                                items: extraProxies.value,
                                page: pageExtraProxies.value,
                                "onUpdate:page": _cache[18] || (_cache[18] = $event => ((pageExtraProxies).value = $event)),
                                "items-per-page": itemsPerPageExtraProxies.value,
                                "items-per-page-options": itemsPerPageOptions.value,
                                "item-key": "name",
                                density: "compact",
                                "hide-default-footer": "",
                                "fixed-header": ""
                              }, {
                                item: _withCtx(({ item, index }) => [
                                  _createElementVNode("tr", null, [
                                    _createElementVNode("td", null, [
                                      _createTextVNode(_toDisplayString(item.name) + " ", 1),
                                      (item.v2ray_link)
                                        ? (_openBlock(), _createBlock(_component_v_btn, {
                                            key: 0,
                                            icon: "",
                                            size: "small",
                                            color: "secondary",
                                            variant: "text",
                                            onClick: $event => (copyToClipboard(item.v2ray_link))
                                          }, {
                                            default: _withCtx(() => [
                                              _createVNode(_component_v_icon, null, {
                                                default: _withCtx(() => _cache[147] || (_cache[147] = [
                                                  _createTextVNode("mdi-link")
                                                ])),
                                                _: 1
                                              })
                                            ]),
                                            _: 2
                                          }, 1032, ["onClick"]))
                                        : _createCommentVNode("", true)
                                    ]),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_chip, {
                                        color: getProxyColor(item.type),
                                        size: "small",
                                        label: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createTextVNode(_toDisplayString(item.type), 1)
                                        ]),
                                        _: 2
                                      }, 1032, ["color"])
                                    ]),
                                    _createElementVNode("td", null, _toDisplayString(item.server), 1),
                                    _createElementVNode("td", null, _toDisplayString(item.port), 1),
                                    _createElementVNode("td", null, [
                                      (isManual(item.source))
                                        ? (_openBlock(), _createBlock(_component_v_icon, {
                                            key: 0,
                                            color: "primary"
                                          }, {
                                            default: _withCtx(() => _cache[148] || (_cache[148] = [
                                              _createTextVNode("mdi-feather")
                                            ])),
                                            _: 1
                                          }))
                                        : (isTemplate(item.source))
                                          ? (_openBlock(), _createBlock(_component_v_icon, {
                                              key: 1,
                                              color: "success"
                                            }, {
                                              default: _withCtx(() => _cache[149] || (_cache[149] = [
                                                _createTextVNode("mdi-file-code-outline")
                                              ])),
                                              _: 1
                                            }))
                                          : (_openBlock(), _createBlock(_component_v_icon, {
                                              key: 2,
                                              color: "info"
                                            }, {
                                              default: _withCtx(() => _cache[150] || (_cache[150] = [
                                                _createTextVNode("mdi-file-download-outline")
                                              ])),
                                              _: 1
                                            }))
                                    ]),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "info",
                                        variant: "text",
                                        onClick: $event => (showProxyGroupYaml(item))
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[151] || (_cache[151] = [
                                              _createTextVNode("mdi-code-json")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick"]),
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "primary",
                                        variant: "text",
                                        onClick: $event => (openProxiesDialog(item))
                                      }, {
                                        default: _withCtx(() => [
                                          (item.overwritten)
                                            ? (_openBlock(), _createBlock(_component_v_icon, { key: 0 }, {
                                                default: _withCtx(() => _cache[152] || (_cache[152] = [
                                                  _createTextVNode("mdi-wrench-check")
                                                ])),
                                                _: 1
                                              }))
                                            : (_openBlock(), _createBlock(_component_v_icon, { key: 1 }, {
                                                default: _withCtx(() => _cache[153] || (_cache[153] = [
                                                  _createTextVNode("mdi-cog")
                                                ])),
                                                _: 1
                                              }))
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick"]),
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "error",
                                        variant: "text",
                                        onClick: $event => (deleteExtraProxies(item.name)),
                                        disabled: !(isManual(item.source)||isInvalid(item.source))
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[154] || (_cache[154] = [
                                              _createTextVNode("mdi-delete")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick", "disabled"])
                                    ])
                                  ])
                                ]),
                                _: 1
                              }, 8, ["headers", "search", "items", "page", "items-per-page", "items-per-page-options"])
                            ]),
                            _createElementVNode("div", _hoisted_37, [
                              _createVNode(_component_v_row, null, {
                                default: _withCtx(() => [
                                  (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(paginatedExtraProxies.value, (item) => {
                                    return (_openBlock(), _createBlock(_component_v_col, {
                                      key: item.name,
                                      cols: "12"
                                    }, {
                                      default: _withCtx(() => [
                                        _createVNode(_component_v_card, {
                                          rounded: "lg",
                                          elevation: "1"
                                        }, {
                                          default: _withCtx(() => [
                                            _createVNode(_component_v_card_title, { class: "d-flex justify-space-between align-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_row, { align: "center" }, {
                                                  default: _withCtx(() => [
                                                    (isManual(item.source))
                                                      ? (_openBlock(), _createBlock(_component_v_icon, {
                                                          key: 0,
                                                          start: "",
                                                          size: "x-small",
                                                          color: "primary"
                                                        }, {
                                                          default: _withCtx(() => _cache[155] || (_cache[155] = [
                                                            _createTextVNode("mdi-feather")
                                                          ])),
                                                          _: 1
                                                        }))
                                                      : (isTemplate(item.source))
                                                        ? (_openBlock(), _createBlock(_component_v_icon, {
                                                            key: 1,
                                                            start: "",
                                                            size: "x-small",
                                                            color: "success"
                                                          }, {
                                                            default: _withCtx(() => _cache[156] || (_cache[156] = [
                                                              _createTextVNode("mdi-file-code-outline")
                                                            ])),
                                                            _: 1
                                                          }))
                                                        : (_openBlock(), _createBlock(_component_v_icon, {
                                                            key: 2,
                                                            start: "",
                                                            size: "x-small",
                                                            color: "info"
                                                          }, {
                                                            default: _withCtx(() => _cache[157] || (_cache[157] = [
                                                              _createTextVNode("mdi-file-download-outline")
                                                            ])),
                                                            _: 1
                                                          })),
                                                    _createElementVNode("span", _hoisted_38, _toDisplayString(item.name), 1),
                                                    (item.v2ray_link)
                                                      ? (_openBlock(), _createBlock(_component_v_btn, {
                                                          key: 3,
                                                          icon: "",
                                                          size: "small",
                                                          color: "secondary",
                                                          variant: "text",
                                                          onClick: $event => (copyToClipboard(item.v2ray_link))
                                                        }, {
                                                          default: _withCtx(() => [
                                                            _createVNode(_component_v_icon, null, {
                                                              default: _withCtx(() => _cache[158] || (_cache[158] = [
                                                                _createTextVNode("mdi-link")
                                                              ])),
                                                              _: 1
                                                            })
                                                          ]),
                                                          _: 2
                                                        }, 1032, ["onClick"]))
                                                      : _createCommentVNode("", true)
                                                  ]),
                                                  _: 2
                                                }, 1024),
                                                _createVNode(_component_v_chip, {
                                                  color: getProxyColor(item.type),
                                                  size: "small",
                                                  label: ""
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createTextVNode(_toDisplayString(item.type), 1)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["color"])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_card_text, null, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", _hoisted_39, [
                                                  _cache[159] || (_cache[159] = _createElementVNode("strong", null, "类型：", -1)),
                                                  _createTextVNode(_toDisplayString(item.type), 1)
                                                ]),
                                                _createElementVNode("div", _hoisted_40, [
                                                  _cache[160] || (_cache[160] = _createElementVNode("strong", null, "服务器：", -1)),
                                                  _createTextVNode(_toDisplayString(item.server), 1)
                                                ])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_divider),
                                            _createVNode(_component_v_card_actions, { class: "d-flex justify-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "primary",
                                                  variant: "text",
                                                  onClick: $event => (openProxiesDialog(item))
                                                }, {
                                                  default: _withCtx(() => [
                                                    (item.overwritten)
                                                      ? (_openBlock(), _createBlock(_component_v_icon, { key: 0 }, {
                                                          default: _withCtx(() => _cache[161] || (_cache[161] = [
                                                            _createTextVNode("mdi-wrench-check")
                                                          ])),
                                                          _: 1
                                                        }))
                                                      : (_openBlock(), _createBlock(_component_v_icon, { key: 1 }, {
                                                          default: _withCtx(() => _cache[162] || (_cache[162] = [
                                                            _createTextVNode("mdi-cog")
                                                          ])),
                                                          _: 1
                                                        }))
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick"]),
                                                _createVNode(_component_v_spacer),
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "info",
                                                  variant: "text",
                                                  onClick: $event => (showProxyGroupYaml(item))
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[163] || (_cache[163] = [
                                                        _createTextVNode("mdi-code-json")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick"]),
                                                _createVNode(_component_v_spacer),
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "error",
                                                  variant: "text",
                                                  onClick: $event => (deleteExtraProxies(item.name)),
                                                  disabled: !isManual(item.source)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[164] || (_cache[164] = [
                                                        _createTextVNode("mdi-delete")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick", "disabled"])
                                              ]),
                                              _: 2
                                            }, 1024)
                                          ]),
                                          _: 2
                                        }, 1024)
                                      ]),
                                      _: 2
                                    }, 1024))
                                  }), 128))
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_41, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1"
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "8",
                                    md: "10",
                                    class: "d-flex justify-center"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageExtraProxies.value,
                                        "onUpdate:modelValue": _cache[19] || (_cache[19] = $event => ((pageExtraProxies).value = $event)),
                                        length: pageCountExtraProxies.value,
                                        "total-visible": "5",
                                        class: "d-none d-sm-flex my-0",
                                        rounded: "circle"
                                      }, null, 8, ["modelValue", "length"]),
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageExtraProxies.value,
                                        "onUpdate:modelValue": _cache[20] || (_cache[20] = $event => ((pageExtraProxies).value = $event)),
                                        length: pageCountExtraProxies.value,
                                        "total-visible": "0",
                                        class: "d-sm-none my-0",
                                        rounded: "circle"
                                      }, null, 8, ["modelValue", "length"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_menu, null, {
                                        activator: _withCtx(({ props }) => [
                                          _createVNode(_component_v_btn, _mergeProps(props, {
                                            icon: "",
                                            rounded: "circle",
                                            variant: "tonal"
                                          }), {
                                            default: _withCtx(() => [
                                              _createTextVNode(_toDisplayString(pageTitle(itemsPerPageExtraProxies.value)), 1)
                                            ]),
                                            _: 2
                                          }, 1040)
                                        ]),
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_list, null, {
                                            default: _withCtx(() => [
                                              (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(itemsPerPageOptions.value, (item, index) => {
                                                return (_openBlock(), _createBlock(_component_v_list_item, {
                                                  key: index,
                                                  value: item.value,
                                                  onClick: $event => (itemsPerPageExtraProxies.value = item.value)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_list_item_title, null, {
                                                      default: _withCtx(() => [
                                                        _createTextVNode(_toDisplayString(item.title), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["value", "onClick"]))
                                              }), 128))
                                            ]),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createVNode(_component_v_divider)
                          ])
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_window_item, null, {
                        default: _withCtx(() => [
                          _createElementVNode("div", _hoisted_42, [
                            _createElementVNode("div", _hoisted_43, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "10",
                                    sm: "6",
                                    class: "d-flex justify-start"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_text_field, {
                                        modelValue: searchRuleProviders.value,
                                        "onUpdate:modelValue": _cache[21] || (_cache[21] = $event => ((searchRuleProviders).value = $event)),
                                        label: "搜索规则集合",
                                        clearable: "",
                                        density: "compact",
                                        variant: "solo-filled",
                                        "hide-details": "",
                                        class: "search-field",
                                        "prepend-inner-icon": "mdi-magnify",
                                        flat: "",
                                        rounded: "pill",
                                        "single-line": ""
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    sm: "6",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_btn, {
                                        color: "primary",
                                        onClick: openAddRuleProviderDialog,
                                        icon: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[165] || (_cache[165] = [
                                              _createTextVNode("mdi-plus")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_44, [
                              _createVNode(_component_v_data_table, {
                                headers: headersRuleProviders.value,
                                items: extraRuleProviders.value,
                                search: searchRuleProviders.value,
                                page: pageRulProviders.value,
                                "onUpdate:page": _cache[22] || (_cache[22] = $event => ((pageRulProviders).value = $event)),
                                "items-per-page": itemsPerPageRuleProviders.value,
                                "items-per-page-options": itemsPerPageOptions.value,
                                "item-key": "name",
                                class: "px-4",
                                density: "compact",
                                "hide-default-footer": "",
                                "fixed-header": ""
                              }, {
                                item: _withCtx(({ item }) => [
                                  _createElementVNode("tr", null, [
                                    _createElementVNode("td", null, _toDisplayString(item.name), 1),
                                    _createElementVNode("td", null, _toDisplayString(item.type), 1),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_chip, {
                                        color: getBehaviorColor(item.behavior),
                                        size: "small",
                                        label: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createTextVNode(_toDisplayString(item.behavior), 1)
                                        ]),
                                        _: 2
                                      }, 1032, ["color"])
                                    ]),
                                    _createElementVNode("td", null, _toDisplayString(item.format), 1),
                                    _createElementVNode("td", null, [
                                      (isManual(item.source))
                                        ? (_openBlock(), _createBlock(_component_v_icon, {
                                            key: 0,
                                            color: "primary"
                                          }, {
                                            default: _withCtx(() => _cache[166] || (_cache[166] = [
                                              _createTextVNode("mdi-feather")
                                            ])),
                                            _: 1
                                          }))
                                        : (isTemplate(item.source))
                                          ? (_openBlock(), _createBlock(_component_v_icon, {
                                              key: 1,
                                              color: "success"
                                            }, {
                                              default: _withCtx(() => _cache[167] || (_cache[167] = [
                                                _createTextVNode("mdi-file-code-outline")
                                              ])),
                                              _: 1
                                            }))
                                          : (_openBlock(), _createBlock(_component_v_icon, {
                                              key: 2,
                                              color: "info"
                                            }, {
                                              default: _withCtx(() => _cache[168] || (_cache[168] = [
                                                _createTextVNode("mdi-file-download-outline")
                                              ])),
                                              _: 1
                                            }))
                                    ]),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "primary",
                                        variant: "text",
                                        onClick: $event => (editRuleProvider(item.name)),
                                        disabled: !isManual(item.source)
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[169] || (_cache[169] = [
                                              _createTextVNode("mdi-pencil")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick", "disabled"]),
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "error",
                                        variant: "text",
                                        onClick: $event => (deleteRuleProvider(item.name)),
                                        disabled: !isManual(item.source)
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[170] || (_cache[170] = [
                                              _createTextVNode("mdi-delete")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick", "disabled"]),
                                      (!isManual(item.source))
                                        ? (_openBlock(), _createBlock(_component_v_tooltip, {
                                            key: 0,
                                            activator: "parent",
                                            location: "top"
                                          }, {
                                            default: _withCtx(() => _cache[171] || (_cache[171] = [
                                              _createTextVNode(" 非手动添加 ")
                                            ])),
                                            _: 1
                                          }))
                                        : _createCommentVNode("", true)
                                    ])
                                  ])
                                ]),
                                _: 1
                              }, 8, ["headers", "items", "search", "page", "items-per-page", "items-per-page-options"])
                            ]),
                            _createElementVNode("div", _hoisted_45, [
                              _createVNode(_component_v_row, null, {
                                default: _withCtx(() => [
                                  (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(paginatedExtraRuleProviders.value, (item) => {
                                    return (_openBlock(), _createBlock(_component_v_col, {
                                      key: item.name,
                                      cols: "12"
                                    }, {
                                      default: _withCtx(() => [
                                        _createVNode(_component_v_card, {
                                          rounded: "lg",
                                          elevation: "1"
                                        }, {
                                          default: _withCtx(() => [
                                            _createVNode(_component_v_card_title, { class: "d-flex justify-space-between align-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_row, { align: "center" }, {
                                                  default: _withCtx(() => [
                                                    (isManual(item.source))
                                                      ? (_openBlock(), _createBlock(_component_v_icon, {
                                                          key: 0,
                                                          start: "",
                                                          size: "x-small",
                                                          color: "primary"
                                                        }, {
                                                          default: _withCtx(() => _cache[172] || (_cache[172] = [
                                                            _createTextVNode("mdi-feather")
                                                          ])),
                                                          _: 1
                                                        }))
                                                      : (isTemplate(item.source))
                                                        ? (_openBlock(), _createBlock(_component_v_icon, {
                                                            key: 1,
                                                            start: "",
                                                            size: "x-small",
                                                            color: "success"
                                                          }, {
                                                            default: _withCtx(() => _cache[173] || (_cache[173] = [
                                                              _createTextVNode("mdi-file-code-outline")
                                                            ])),
                                                            _: 1
                                                          }))
                                                        : (_openBlock(), _createBlock(_component_v_icon, {
                                                            key: 2,
                                                            start: "",
                                                            size: "x-small",
                                                            color: "info"
                                                          }, {
                                                            default: _withCtx(() => _cache[174] || (_cache[174] = [
                                                              _createTextVNode("mdi-file-download-outline")
                                                            ])),
                                                            _: 1
                                                          })),
                                                    _createElementVNode("span", _hoisted_46, _toDisplayString(item.name), 1)
                                                  ]),
                                                  _: 2
                                                }, 1024),
                                                _createVNode(_component_v_chip, {
                                                  color: getBehaviorColor(item.behavior),
                                                  size: "small",
                                                  label: ""
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createTextVNode(_toDisplayString(item.behavior), 1)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["color"])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_card_text, null, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", _hoisted_47, [
                                                  _cache[175] || (_cache[175] = _createElementVNode("strong", null, "类型：", -1)),
                                                  _createTextVNode(_toDisplayString(item.type), 1)
                                                ]),
                                                _createElementVNode("div", _hoisted_48, [
                                                  _cache[176] || (_cache[176] = _createElementVNode("strong", null, "内容：", -1)),
                                                  _createTextVNode(_toDisplayString(item.format), 1)
                                                ])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_divider),
                                            _createVNode(_component_v_card_actions, { class: "d-flex justify-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "primary",
                                                  variant: "text",
                                                  onClick: $event => (editRuleProvider(item.name)),
                                                  disabled: !isManual(item.source)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[177] || (_cache[177] = [
                                                        _createTextVNode("mdi-pencil")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick", "disabled"]),
                                                _createVNode(_component_v_spacer),
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "error",
                                                  variant: "text",
                                                  onClick: $event => (deleteRuleProvider(item.name)),
                                                  disabled: !isManual(item.source)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[178] || (_cache[178] = [
                                                        _createTextVNode("mdi-delete")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick", "disabled"])
                                              ]),
                                              _: 2
                                            }, 1024)
                                          ]),
                                          _: 2
                                        }, 1024)
                                      ]),
                                      _: 2
                                    }, 1024))
                                  }), 128))
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_49, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1"
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "8",
                                    md: "10",
                                    class: "d-flex justify-center"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageRulProviders.value,
                                        "onUpdate:modelValue": _cache[23] || (_cache[23] = $event => ((pageRulProviders).value = $event)),
                                        length: pageCountExtraRuleProviders.value,
                                        "total-visible": "5",
                                        rounded: "circle",
                                        class: "d-none d-sm-flex my-0"
                                      }, null, 8, ["modelValue", "length"]),
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageRulProviders.value,
                                        "onUpdate:modelValue": _cache[24] || (_cache[24] = $event => ((pageRulProviders).value = $event)),
                                        length: pageCountExtraRuleProviders.value,
                                        "total-visible": "0",
                                        rounded: "circle",
                                        class: "d-sm-none my-0"
                                      }, null, 8, ["modelValue", "length"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_menu, null, {
                                        activator: _withCtx(({ props }) => [
                                          _createVNode(_component_v_btn, _mergeProps(props, {
                                            icon: "",
                                            rounded: "circle",
                                            variant: "tonal"
                                          }), {
                                            default: _withCtx(() => [
                                              _createTextVNode(_toDisplayString(pageTitle(itemsPerPageRuleProviders.value)), 1)
                                            ]),
                                            _: 2
                                          }, 1040)
                                        ]),
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_list, null, {
                                            default: _withCtx(() => [
                                              (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(itemsPerPageOptions.value, (item, index) => {
                                                return (_openBlock(), _createBlock(_component_v_list_item, {
                                                  key: index,
                                                  value: item.value,
                                                  onClick: $event => (itemsPerPageRuleProviders.value = item.value)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_list_item_title, null, {
                                                      default: _withCtx(() => [
                                                        _createTextVNode(_toDisplayString(item.title), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["value", "onClick"]))
                                              }), 128))
                                            ]),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createVNode(_component_v_divider)
                          ])
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_window_item, null, {
                        default: _withCtx(() => [
                          _createElementVNode("div", _hoisted_50, [
                            _createElementVNode("div", _hoisted_51, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "10",
                                    sm: "6",
                                    class: "d-flex justify-start"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_text_field, {
                                        modelValue: searchHosts.value,
                                        "onUpdate:modelValue": _cache[25] || (_cache[25] = $event => ((searchHosts).value = $event)),
                                        label: "搜索Hosts",
                                        clearable: "",
                                        density: "compact",
                                        variant: "solo-filled",
                                        "hide-details": "",
                                        class: "search-field",
                                        "prepend-inner-icon": "mdi-magnify",
                                        flat: "",
                                        rounded: "pill",
                                        "single-line": ""
                                      }, null, 8, ["modelValue"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    sm: "6",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_btn, {
                                        color: "primary",
                                        onClick: openAddHostDialog,
                                        icon: ""
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[179] || (_cache[179] = [
                                              _createTextVNode("mdi-plus")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_52, [
                              _createVNode(_component_v_data_table, {
                                headers: headersHosts.value,
                                items: hosts.value,
                                search: searchHosts.value,
                                page: pageHosts.value,
                                "onUpdate:page": _cache[26] || (_cache[26] = $event => ((pageHosts).value = $event)),
                                "items-per-page": itemsPerPageHosts.value,
                                "items-per-page-options": itemsPerPageOptions.value,
                                class: "px-4",
                                density: "compact",
                                "hide-default-footer": "",
                                "fixed-header": "",
                                "item-key": "domain"
                              }, {
                                item: _withCtx(({ item }) => [
                                  _createElementVNode("tr", null, [
                                    _createElementVNode("td", null, _toDisplayString(item.domain), 1),
                                    _createElementVNode("td", null, [
                                      (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(item.value, (ip) => {
                                        return (_openBlock(), _createBlock(_component_v_chip, {
                                          key: ip,
                                          size: "small",
                                          class: "ma-1"
                                        }, {
                                          default: _withCtx(() => [
                                            _createTextVNode(_toDisplayString(ip), 1)
                                          ]),
                                          _: 2
                                        }, 1024))
                                      }), 128))
                                    ]),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_chip, {
                                        color: getBoolColor(item.using_cloudflare),
                                        size: "small"
                                      }, {
                                        default: _withCtx(() => [
                                          _createTextVNode(_toDisplayString(item.using_cloudflare ? '是' : '否'), 1)
                                        ]),
                                        _: 2
                                      }, 1032, ["color"])
                                    ]),
                                    _createElementVNode("td", null, [
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "primary",
                                        variant: "text",
                                        onClick: $event => (editHost(item.domain))
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[180] || (_cache[180] = [
                                              _createTextVNode("mdi-pencil")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick"]),
                                      _createVNode(_component_v_btn, {
                                        icon: "",
                                        size: "small",
                                        color: "error",
                                        variant: "text",
                                        onClick: $event => (deleteHost(item.domain))
                                      }, {
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_icon, null, {
                                            default: _withCtx(() => _cache[181] || (_cache[181] = [
                                              _createTextVNode("mdi-delete")
                                            ])),
                                            _: 1
                                          })
                                        ]),
                                        _: 2
                                      }, 1032, ["onClick"])
                                    ])
                                  ])
                                ]),
                                _: 1
                              }, 8, ["headers", "items", "search", "page", "items-per-page", "items-per-page-options"])
                            ]),
                            _createElementVNode("div", _hoisted_53, [
                              _createVNode(_component_v_row, null, {
                                default: _withCtx(() => [
                                  (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(paginatedHosts.value, (item) => {
                                    return (_openBlock(), _createBlock(_component_v_col, {
                                      key: item.domain,
                                      cols: "12"
                                    }, {
                                      default: _withCtx(() => [
                                        _createVNode(_component_v_card, {
                                          rounded: "lg",
                                          elevation: "1"
                                        }, {
                                          default: _withCtx(() => [
                                            _createVNode(_component_v_card_title, { class: "d-flex justify-space-between align-center" }, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", null, [
                                                  _createElementVNode("span", _hoisted_54, _toDisplayString(item.domain), 1)
                                                ]),
                                                _createVNode(_component_v_chip, {
                                                  color: getBoolColor(item.using_cloudflare),
                                                  size: "small",
                                                  label: ""
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createTextVNode(_toDisplayString(item.using_cloudflare ? 'Cloudflare' : 'hosts'), 1)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["color"])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_divider),
                                            _createVNode(_component_v_card_text, null, {
                                              default: _withCtx(() => [
                                                _createElementVNode("div", _hoisted_55, [
                                                  _cache[182] || (_cache[182] = _createElementVNode("strong", null, "IP：", -1)),
                                                  (_openBlock(true), _createElementBlock(_Fragment, null, _renderList((item.using_cloudflare? bestCloudflareIPs.value : item.value), (ip) => {
                                                    return (_openBlock(), _createBlock(_component_v_chip, {
                                                      key: ip,
                                                      size: "small",
                                                      class: "ma-1"
                                                    }, {
                                                      default: _withCtx(() => [
                                                        _createTextVNode(_toDisplayString(ip), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024))
                                                  }), 128))
                                                ])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_divider),
                                            _createVNode(_component_v_card_actions, { class: "d-flex justify-center" }, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "primary",
                                                  variant: "text",
                                                  onClick: $event => (editHost(item.domain))
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[183] || (_cache[183] = [
                                                        _createTextVNode("mdi-pencil")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick"]),
                                                _createVNode(_component_v_spacer),
                                                _createVNode(_component_v_btn, {
                                                  icon: "",
                                                  size: "small",
                                                  color: "error",
                                                  variant: "text",
                                                  onClick: $event => (deleteHost(item.domain))
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[184] || (_cache[184] = [
                                                        _createTextVNode("mdi-delete")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick"])
                                              ]),
                                              _: 2
                                            }, 1024)
                                          ]),
                                          _: 2
                                        }, 1024)
                                      ]),
                                      _: 2
                                    }, 1024))
                                  }), 128))
                                ]),
                                _: 1
                              })
                            ]),
                            _createElementVNode("div", _hoisted_56, [
                              _createVNode(_component_v_row, {
                                align: "center",
                                "no-gutters": ""
                              }, {
                                default: _withCtx(() => [
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1"
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "8",
                                    md: "10",
                                    class: "d-flex justify-center"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageHosts.value,
                                        "onUpdate:modelValue": _cache[27] || (_cache[27] = $event => ((pageHosts).value = $event)),
                                        length: pageCountHosts.value,
                                        "total-visible": "5",
                                        rounded: "circle",
                                        class: "d-none d-sm-flex my-0"
                                      }, null, 8, ["modelValue", "length"]),
                                      _createVNode(_component_v_pagination, {
                                        modelValue: pageHosts.value,
                                        "onUpdate:modelValue": _cache[28] || (_cache[28] = $event => ((pageHosts).value = $event)),
                                        length: pageCountHosts.value,
                                        "total-visible": "0",
                                        rounded: "circle",
                                        class: "d-sm-none my-0"
                                      }, null, 8, ["modelValue", "length"])
                                    ]),
                                    _: 1
                                  }),
                                  _createVNode(_component_v_col, {
                                    cols: "2",
                                    md: "1",
                                    class: "d-flex justify-end"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_menu, null, {
                                        activator: _withCtx(({ props }) => [
                                          _createVNode(_component_v_btn, _mergeProps(props, {
                                            icon: "",
                                            rounded: "circle",
                                            variant: "tonal"
                                          }), {
                                            default: _withCtx(() => [
                                              _createTextVNode(_toDisplayString(pageTitle(itemsPerPageHosts.value)), 1)
                                            ]),
                                            _: 2
                                          }, 1040)
                                        ]),
                                        default: _withCtx(() => [
                                          _createVNode(_component_v_list, null, {
                                            default: _withCtx(() => [
                                              (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(itemsPerPageOptions.value, (item, index) => {
                                                return (_openBlock(), _createBlock(_component_v_list_item, {
                                                  key: index,
                                                  value: item.value,
                                                  onClick: $event => (itemsPerPageHosts.value = item.value)
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_list_item_title, null, {
                                                      default: _withCtx(() => [
                                                        _createTextVNode(_toDisplayString(item.title), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024)
                                                  ]),
                                                  _: 2
                                                }, 1032, ["value", "onClick"]))
                                              }), 128))
                                            ]),
                                            _: 1
                                          })
                                        ]),
                                        _: 1
                                      })
                                    ]),
                                    _: 1
                                  })
                                ]),
                                _: 1
                              })
                            ]),
                            _createVNode(_component_v_divider)
                          ])
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_window_item, null, {
                        default: _withCtx(() => [
                          _createElementVNode("div", _hoisted_57, [
                            (Object.keys(subscriptionsInfo.value).length === 0)
                              ? (_openBlock(), _createBlock(_component_v_row, {
                                  key: 0,
                                  class: "pa-6 justify-center"
                                }, {
                                  default: _withCtx(() => [
                                    _createVNode(_component_v_card, {
                                      class: "mx-auto text-center py-8 px-4",
                                      "max-width": "400",
                                      elevation: "10",
                                      rounded: "xl",
                                      style: {"background":"linear-gradient(135deg, #d6c355 0%, #fda085 100%)"}
                                    }, {
                                      default: _withCtx(() => [
                                        _createVNode(_component_v_card_text, { class: "d-flex flex-column align-center" }, {
                                          default: _withCtx(() => [
                                            _createVNode(_component_v_icon, {
                                              size: "64",
                                              color: "white",
                                              class: "mb-4 bounce"
                                            }, {
                                              default: _withCtx(() => _cache[185] || (_cache[185] = [
                                                _createTextVNode(" mdi-emoticon-happy-outline ")
                                              ])),
                                              _: 1
                                            }),
                                            _cache[187] || (_cache[187] = _createElementVNode("h2", { class: "text-h6 font-weight-bold white--text mb-2" }, " 还没有订阅呢 🎉 ", -1)),
                                            _cache[188] || (_cache[188] = _createElementVNode("p", { class: "white--text mb-4" }, " 试试添加一个订阅吧！ ", -1)),
                                            _createVNode(_component_v_btn, {
                                              color: "info",
                                              dark: "",
                                              rounded: "",
                                              elevation: "6",
                                              onClick: notifySwitch
                                            }, {
                                              default: _withCtx(() => _cache[186] || (_cache[186] = [
                                                _createTextVNode(" 去配置 🚀 ")
                                              ])),
                                              _: 1
                                            })
                                          ]),
                                          _: 1
                                        })
                                      ]),
                                      _: 1
                                    })
                                  ]),
                                  _: 1
                                }))
                              : _createCommentVNode("", true),
                            _createVNode(_component_v_row, { class: "pa-4" }, {
                              default: _withCtx(() => [
                                (_openBlock(true), _createElementBlock(_Fragment, null, _renderList(subscriptionsInfo.value, (info, url, index) => {
                                  return (_openBlock(), _createBlock(_component_v_col, {
                                    cols: "12",
                                    md: "6"
                                  }, {
                                    default: _withCtx(() => [
                                      _createVNode(_component_v_card, {
                                        variant: "tonal",
                                        class: "subscription-card mb-2 mt-2"
                                      }, {
                                        default: _withCtx(() => [
                                          _createElementVNode("div", _hoisted_58, [
                                            _createVNode(_component_v_card_title, { class: "card-title" }, {
                                              default: _withCtx(() => [
                                                _createTextVNode(_toDisplayString(extractDomain(url)), 1)
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_card_action, null, {
                                              default: _withCtx(() => [
                                                _createVNode(_component_v_btn, {
                                                  class: "card-refresh-button",
                                                  onClick: $event => (updateSubscription(url)),
                                                  loading: refreshingSubscription.value[url]
                                                }, {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, {
                                                      left: "",
                                                      class: "mr-2"
                                                    }, {
                                                      default: _withCtx(() => _cache[189] || (_cache[189] = [
                                                        _createTextVNode(" mdi-refresh ")
                                                      ])),
                                                      _: 1
                                                    }),
                                                    _cache[190] || (_cache[190] = _createTextVNode(" 刷新 "))
                                                  ]),
                                                  _: 2
                                                }, 1032, ["onClick", "loading"])
                                              ]),
                                              _: 2
                                            }, 1024)
                                          ]),
                                          _createVNode(_component_v_card_text, null, {
                                            default: _withCtx(() => [
                                              _createElementVNode("div", _hoisted_59, [
                                                (info.proxy_num != null)
                                                  ? (_openBlock(), _createBlock(_component_v_chip, {
                                                      key: 0,
                                                      size: "small",
                                                      color: "info",
                                                      class: "mr-2"
                                                    }, {
                                                      default: _withCtx(() => [
                                                        _createVNode(_component_v_icon, { class: "mr-2" }, {
                                                          default: _withCtx(() => _cache[191] || (_cache[191] = [
                                                            _createTextVNode(" mdi-server-network ")
                                                          ])),
                                                          _: 1
                                                        }),
                                                        _createTextVNode(" 节点：" + _toDisplayString(info.proxy_num), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024))
                                                  : _createCommentVNode("", true),
                                                (info.last_update)
                                                  ? (_openBlock(), _createBlock(_component_v_chip, {
                                                      key: 1,
                                                      size: "small",
                                                      color: "info",
                                                      class: "mr-2"
                                                    }, {
                                                      default: _withCtx(() => [
                                                        _createVNode(_component_v_icon, { class: "mr-2" }, {
                                                          default: _withCtx(() => _cache[192] || (_cache[192] = [
                                                            _createTextVNode(" mdi-clock-outline ")
                                                          ])),
                                                          _: 1
                                                        }),
                                                        _createTextVNode(" 更新：" + _toDisplayString(formatTimestamp(info.last_update)), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1024))
                                                  : _createCommentVNode("", true),
                                                (info.expire)
                                                  ? (_openBlock(), _createBlock(_component_v_chip, {
                                                      key: 2,
                                                      size: "small",
                                                      color: getExpireColor(info.expire)
                                                    }, {
                                                      default: _withCtx(() => [
                                                        _createVNode(_component_v_icon, { class: "mr-2" }, {
                                                          default: _withCtx(() => _cache[193] || (_cache[193] = [
                                                            _createTextVNode(" mdi-calendar-clock ")
                                                          ])),
                                                          _: 1
                                                        }),
                                                        _createTextVNode(" 到期：" + _toDisplayString(formatTimestamp(info.expire)), 1)
                                                      ]),
                                                      _: 2
                                                    }, 1032, ["color"]))
                                                  : _createCommentVNode("", true)
                                              ]),
                                              _createElementVNode("div", _hoisted_60, [
                                                _cache[194] || (_cache[194] = _createElementVNode("span", null, "已用流量：", -1)),
                                                _createElementVNode("strong", null, _toDisplayString(formatBytes(info.download + info.upload)), 1)
                                              ]),
                                              _createElementVNode("div", _hoisted_61, [
                                                _cache[195] || (_cache[195] = _createElementVNode("span", null, "剩余流量：", -1)),
                                                _createElementVNode("strong", null, _toDisplayString(formatBytes(info.total - info.download)), 1)
                                              ]),
                                              _createVNode(_component_v_progress_linear, {
                                                "model-value": info.used_percentage,
                                                color: getUsageColor(info.used_percentage),
                                                height: "10",
                                                class: "mb-2",
                                                rounded: "",
                                                striped: ""
                                              }, null, 8, ["model-value", "color"]),
                                              _createElementVNode("div", _hoisted_62, [
                                                _createElementVNode("span", null, "下载：" + _toDisplayString(formatBytes(info.download)), 1),
                                                _createElementVNode("span", null, "上传：" + _toDisplayString(formatBytes(info.upload)), 1),
                                                _createElementVNode("span", null, "总量：" + _toDisplayString(formatBytes(info.total)), 1)
                                              ])
                                            ]),
                                            _: 2
                                          }, 1024),
                                          _createVNode(_component_v_divider),
                                          _createElementVNode("div", _hoisted_63, [
                                            _createVNode(_component_v_tooltip, {
                                              location: "top",
                                              text: "复制链接"
                                            }, {
                                              activator: _withCtx(({ props }) => [
                                                _createVNode(_component_v_btn, _mergeProps({ ref_for: true }, props, {
                                                  icon: "",
                                                  size: "small",
                                                  variant: "text",
                                                  onClick: $event => (copyToClipboard(url))
                                                }), {
                                                  default: _withCtx(() => [
                                                    _createVNode(_component_v_icon, null, {
                                                      default: _withCtx(() => _cache[196] || (_cache[196] = [
                                                        _createTextVNode("mdi-content-copy")
                                                      ])),
                                                      _: 1
                                                    })
                                                  ]),
                                                  _: 2
                                                }, 1040, ["onClick"])
                                              ]),
                                              _: 2
                                            }, 1024),
                                            _createVNode(_component_v_tooltip, {
                                              location: "top",
                                              text: "启用自动更新"
                                            }, {
                                              activator: _withCtx(({ props }) => [
                                                _createVNode(_component_v_switch, _mergeProps({
                                                  modelValue: info.enabled,
                                                  "onUpdate:modelValue": $event => ((info.enabled) = $event),
                                                  ref_for: true
                                                }, props, {
                                                  onChange: $event => (toggleSubscription(url, info.enabled))
                                                }), null, 16, ["modelValue", "onUpdate:modelValue", "onChange"])
                                              ]),
                                              _: 2
                                            }, 1024)
                                          ])
                                        ]),
                                        _: 2
                                      }, 1024)
                                    ]),
                                    _: 2
                                  }, 1024))
                                }), 256))
                              ]),
                              _: 1
                            })
                          ])
                        ]),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"])
                ]))
          ]),
          _: 1
        }),
        _createVNode(_component_v_expand_transition, null, {
          default: _withCtx(() => [
            (expand.value)
              ? (_openBlock(), _createElementBlock("div", _hoisted_64, [
                  _createVNode(_component_v_row, { dense: "" }, {
                    default: _withCtx(() => [
                      _createVNode(_component_v_col, {
                        cols: "6",
                        md: "3"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_card, {
                            class: "pa-4 d-flex flex-column align-center",
                            rounded: "xl"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                size: "40",
                                color: "primary"
                              }, {
                                default: _withCtx(() => _cache[197] || (_cache[197] = [
                                  _createTextVNode("mdi-format-list-bulleted")
                                ])),
                                _: 1
                              }),
                              _createElementVNode("div", _hoisted_65, _toDisplayString(sortedRulesetRules.value.length), 1),
                              _cache[198] || (_cache[198] = _createElementVNode("div", { class: "text-subtitle-2 grey--text" }, "规则集规则", -1))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_col, {
                        cols: "6",
                        md: "3"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_card, {
                            class: "pa-4 d-flex flex-column align-center",
                            rounded: "xl"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                size: "40",
                                color: "info"
                              }, {
                                default: _withCtx(() => _cache[199] || (_cache[199] = [
                                  _createTextVNode("mdi-pin")
                                ])),
                                _: 1
                              }),
                              _createElementVNode("div", _hoisted_66, _toDisplayString(sortedRules.value.length), 1),
                              _cache[200] || (_cache[200] = _createElementVNode("div", { class: "text-subtitle-2 grey--text" }, "置顶规则", -1))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_col, {
                        cols: "6",
                        md: "3"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_card, {
                            class: "pa-4 d-flex flex-column align-center",
                            rounded: "xl"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                size: "40",
                                color: "success"
                              }, {
                                default: _withCtx(() => _cache[201] || (_cache[201] = [
                                  _createTextVNode("mdi-source-branch")
                                ])),
                                _: 1
                              }),
                              _createElementVNode("div", _hoisted_67, _toDisplayString(proxyGroups.value.length), 1),
                              _cache[202] || (_cache[202] = _createElementVNode("div", { class: "text-subtitle-2 grey--text" }, "代理组", -1))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_col, {
                        cols: "6",
                        md: "3"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_card, {
                            class: "pa-4 d-flex flex-column align-center",
                            rounded: "xl"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                size: "40",
                                color: "error"
                              }, {
                                default: _withCtx(() => _cache[203] || (_cache[203] = [
                                  _createTextVNode("mdi-rocket-launch")
                                ])),
                                _: 1
                              }),
                              _createElementVNode("div", _hoisted_68, _toDisplayString(extraProxies.value.length), 1),
                              _cache[204] || (_cache[204] = _createElementVNode("div", { class: "text-subtitle-2 grey--text" }, "出站代理", -1))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_col, {
                        cols: "6",
                        md: "3"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_card, {
                            class: "pa-4 d-flex flex-column align-center",
                            rounded: "xl"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                size: "40",
                                color: "warning"
                              }, {
                                default: _withCtx(() => _cache[205] || (_cache[205] = [
                                  _createTextVNode("mdi-folder-multiple")
                                ])),
                                _: 1
                              }),
                              _createElementVNode("div", _hoisted_69, _toDisplayString(extraRuleProviders.value.length), 1),
                              _cache[206] || (_cache[206] = _createElementVNode("div", { class: "text-subtitle-2 grey--text" }, "规则集合", -1))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_col, {
                        cols: "6",
                        md: "3"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_card, {
                            class: "pa-4 d-flex flex-column align-center",
                            rounded: "xl"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                size: "40",
                                color: "secondary"
                              }, {
                                default: _withCtx(() => _cache[207] || (_cache[207] = [
                                  _createTextVNode("mdi-lan")
                                ])),
                                _: 1
                              }),
                              _createElementVNode("div", _hoisted_70, _toDisplayString(hosts.value.length), 1),
                              _cache[208] || (_cache[208] = _createElementVNode("div", { class: "text-subtitle-2 grey--text" }, "Hosts", -1))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_col, {
                        cols: "6",
                        md: "3"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_card, {
                            class: "pa-4 d-flex flex-column align-center",
                            rounded: "xl"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                size: "40",
                                color: "info"
                              }, {
                                default: _withCtx(() => _cache[209] || (_cache[209] = [
                                  _createTextVNode("mdi-earth")
                                ])),
                                _: 1
                              }),
                              _createElementVNode("div", _hoisted_71, _toDisplayString(geoRules.value.geosite.length), 1),
                              _cache[210] || (_cache[210] = _createElementVNode("div", { class: "text-subtitle-2 grey--text" }, "Geosite", -1))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }),
                      _createVNode(_component_v_col, {
                        cols: "6",
                        md: "3"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_card, {
                            class: "pa-4 d-flex flex-column align-center",
                            rounded: "xl"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                size: "40",
                                color: "success"
                              }, {
                                default: _withCtx(() => _cache[211] || (_cache[211] = [
                                  _createTextVNode("mdi-clock-time-four-outline")
                                ])),
                                _: 1
                              }),
                              _createElementVNode("div", _hoisted_72, _toDisplayString(lastUpdated.value), 1),
                              _cache[212] || (_cache[212] = _createElementVNode("div", { class: "text-subtitle-2 grey--text" }, "最后更新", -1))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      })
                    ]),
                    _: 1
                  })
                ]))
              : _createCommentVNode("", true)
          ]),
          _: 1
        }),
        _createVNode(_component_v_card_actions, null, {
          default: _withCtx(() => [
            _createVNode(_component_v_btn, {
              color: "primary",
              onClick: refreshData,
              loading: loading.value
            }, {
              default: _withCtx(() => [
                _createVNode(_component_v_icon, { left: "" }, {
                  default: _withCtx(() => _cache[213] || (_cache[213] = [
                    _createTextVNode("mdi-refresh")
                  ])),
                  _: 1
                }),
                _cache[214] || (_cache[214] = _createTextVNode(" 刷新数据 "))
              ]),
              _: 1
            }, 8, ["loading"]),
            _createVNode(_component_v_btn, {
              color: "info",
              href: subUrl.value,
              target: "_blank"
            }, {
              default: _withCtx(() => [
                _createVNode(_component_v_icon, { left: "" }, {
                  default: _withCtx(() => _cache[215] || (_cache[215] = [
                    _createTextVNode("mdi-link-variant")
                  ])),
                  _: 1
                }),
                _cache[216] || (_cache[216] = _createTextVNode(" 生成链接 "))
              ]),
              _: 1
            }, 8, ["href"]),
            _createVNode(_component_v_btn, {
              color: "success",
              onClick: _cache[30] || (_cache[30] = $event => (expand.value = !expand.value))
            }, {
              default: _withCtx(() => [
                _createVNode(_component_v_icon, { left: "" }, {
                  default: _withCtx(() => _cache[217] || (_cache[217] = [
                    _createTextVNode("mdi-chart-bar")
                  ])),
                  _: 1
                }),
                _cache[218] || (_cache[218] = _createTextVNode(" 统计信息 "))
              ]),
              _: 1
            }),
            _createVNode(_component_v_spacer),
            _createVNode(_component_v_btn, {
              color: "primary",
              onClick: notifySwitch
            }, {
              default: _withCtx(() => [
                _createVNode(_component_v_icon, { left: "" }, {
                  default: _withCtx(() => _cache[219] || (_cache[219] = [
                    _createTextVNode("mdi-cog")
                  ])),
                  _: 1
                }),
                _cache[220] || (_cache[220] = _createTextVNode(" 配置 "))
              ]),
              _: 1
            })
          ]),
          _: 1
        }),
        _createVNode(_component_v_snackbar, {
          modelValue: snackbar.value.show,
          "onUpdate:modelValue": _cache[31] || (_cache[31] = $event => ((snackbar.value.show) = $event)),
          color: snackbar.value.color,
          location: "bottom",
          class: "mb-2"
        }, {
          default: _withCtx(() => [
            _createTextVNode(_toDisplayString(snackbar.value.message), 1)
          ]),
          _: 1
        }, 8, ["modelValue", "color"])
      ]),
      _: 1
    }),
    (ruleDialogVisible.value)
      ? (_openBlock(), _createBlock(_sfc_main$1, {
          key: 0,
          "initial-rule": currentRule.value,
          loading: saveRuleLoading.value,
          "is-adding-rule": editingPriority.value === null,
          "editing-type": editingType.value,
          "rule-provider-names": ruleProviderNames.value,
          "geo-ip": geoRules.value.geoip,
          "geo-site": geoRules.value.geosite,
          "custom-outbounds": customOutbounds.value,
          onSave: saveRule,
          showDialog: ruleDialogVisible.value,
          "onUpdate:showDialog": _cache[32] || (_cache[32] = $event => ((ruleDialogVisible).value = $event))
        }, null, 8, ["initial-rule", "loading", "is-adding-rule", "editing-type", "rule-provider-names", "geo-ip", "geo-site", "custom-outbounds", "showDialog"]))
      : _createCommentVNode("", true),
    _createVNode(_component_v_dialog, {
      modelValue: proxyGroupDialog.value,
      "onUpdate:modelValue": _cache[59] || (_cache[59] = $event => ((proxyGroupDialog).value = $event)),
      "max-width": "40rem"
    }, {
      default: _withCtx(() => [
        _createVNode(_component_v_form, {
          ref_key: "proxyGroupsForm",
          ref: proxyGroupsForm,
          onSubmit: _withModifiers(saveProxyGroups, ["prevent"])
        }, {
          default: _withCtx(() => [
            _createVNode(_component_v_card, null, {
              default: _withCtx(() => [
                _createVNode(_component_v_card_title, null, {
                  default: _withCtx(() => [
                    _createTextVNode(_toDisplayString(editingProxyGroupName.value === null ? '添加代理组' : '编辑代理组'), 1)
                  ]),
                  _: 1
                }),
                _createVNode(_component_v_card_text, {
                  style: {"overflow-y":"auto"},
                  "max-height": "60rem"
                }, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_row, null, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value.name,
                              "onUpdate:modelValue": _cache[33] || (_cache[33] = $event => ((newProxyGroup.value.name) = $event)),
                              label: "name",
                              required: "",
                              hint: "策略组的名字",
                              rules: [v => !!v || 'Name不能为空'],
                              class: "mb-4"
                            }, null, 8, ["modelValue", "rules"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_select, {
                              modelValue: newProxyGroup.value.type,
                              "onUpdate:modelValue": _cache[34] || (_cache[34] = $event => ((newProxyGroup.value.type) = $event)),
                              label: "type",
                              items: proxyGroupTypes.value,
                              required: "",
                              hint: "策略组的类型",
                              class: "mb-4"
                            }, null, 8, ["modelValue", "items"])
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    }),
                    _createVNode(_component_v_select, {
                      modelValue: newProxyGroup.value.proxies,
                      "onUpdate:modelValue": _cache[35] || (_cache[35] = $event => ((newProxyGroup.value.proxies) = $event)),
                      label: "proxies",
                      items: actions.value,
                      multiple: "",
                      chips: "",
                      clearable: "",
                      hint: "引入出站代理或其他策略组",
                      class: "mb-4"
                    }, null, 8, ["modelValue", "items"]),
                    _createVNode(_component_v_select, {
                      modelValue: newProxyGroup.value.use,
                      "onUpdate:modelValue": _cache[36] || (_cache[36] = $event => ((newProxyGroup.value.use) = $event)),
                      label: "use",
                      items: proxyProviderNames.value,
                      multiple: "",
                      chips: "",
                      clearable: "",
                      hint: "引入代理集合",
                      class: "mb-4"
                    }, null, 8, ["modelValue", "items"]),
                    _createVNode(_component_v_text_field, {
                      modelValue: newProxyGroup.value.url,
                      "onUpdate:modelValue": _cache[37] || (_cache[37] = $event => ((newProxyGroup.value.url) = $event)),
                      label: "url",
                      hint: "健康检查测试地址",
                      rules: urlRules,
                      clearable: "",
                      class: "mb-4"
                    }, null, 8, ["modelValue"]),
                    (newProxyGroup.value.type === 'url-test')
                      ? (_openBlock(), _createBlock(_component_v_text_field, {
                          key: 0,
                          modelValue: newProxyGroup.value.tolerance,
                          "onUpdate:modelValue": _cache[38] || (_cache[38] = $event => ((newProxyGroup.value.tolerance) = $event)),
                          modelModifiers: { number: true },
                          label: "tolerance (ms)",
                          variant: "outlined",
                          type: "number",
                          min: "10",
                          hint: "节点切换容差",
                          rules: [v => v >=0  || '容差需不小于0'],
                          class: "mb-4"
                        }, null, 8, ["modelValue", "rules"]))
                      : _createCommentVNode("", true),
                    (newProxyGroup.value.type === 'load-balance')
                      ? (_openBlock(), _createBlock(_component_v_select, {
                          key: 1,
                          modelValue: newProxyGroup.value.strategy,
                          "onUpdate:modelValue": _cache[39] || (_cache[39] = $event => ((newProxyGroup.value.strategy) = $event)),
                          label: "strategy",
                          items: strategyTypes.value,
                          hint: "负载均衡策略",
                          class: "mb-4"
                        }, null, 8, ["modelValue", "items"]))
                      : _createCommentVNode("", true),
                    (newProxyGroup.value.type === 'smart')
                      ? (_openBlock(), _createBlock(_component_v_select, {
                          key: 2,
                          modelValue: newProxyGroup.value.strategy,
                          "onUpdate:modelValue": _cache[40] || (_cache[40] = $event => ((newProxyGroup.value.strategy) = $event)),
                          label: "strategy",
                          items: smartStrategyTypes.value,
                          hint: "负载均衡策略",
                          class: "mb-4"
                        }, null, 8, ["modelValue", "items"]))
                      : _createCommentVNode("", true),
                    _createVNode(_component_v_row, null, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value['policy-priority'],
                              "onUpdate:modelValue": _cache[41] || (_cache[41] = $event => ((newProxyGroup.value['policy-priority']) = $event)),
                              label: "policy-priority",
                              hint: "优先级"
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value['sample-rate'],
                              "onUpdate:modelValue": _cache[42] || (_cache[42] = $event => ((newProxyGroup.value['sample-rate']) = $event)),
                              label: "sample-rate",
                              hint: "数据采集率"
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    }),
                    _createVNode(_component_v_row, null, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value.filter,
                              "onUpdate:modelValue": _cache[43] || (_cache[43] = $event => ((newProxyGroup.value.filter) = $event)),
                              label: "filter",
                              hint: "筛选满足关键词或正则表达式的节点"
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value['exclude-filter'],
                              "onUpdate:modelValue": _cache[44] || (_cache[44] = $event => ((newProxyGroup.value['exclude-filter']) = $event)),
                              label: "exclude-filter",
                              hint: "排除满足关键词或正则表达式的节点"
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value['exclude-type'],
                              "onUpdate:modelValue": _cache[45] || (_cache[45] = $event => ((newProxyGroup.value['exclude-type']) = $event)),
                              label: "exclude-type",
                              hint: "不支持正则表达式，通过 | 分割"
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value['expected-status'],
                              "onUpdate:modelValue": _cache[46] || (_cache[46] = $event => ((newProxyGroup.value['expected-status']) = $event)),
                              label: "expected-status",
                              hint: "健康检查时期望的 HTTP 响应状态码"
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    }),
                    _createVNode(_component_v_row, null, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "12"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value.icon,
                              "onUpdate:modelValue": _cache[47] || (_cache[47] = $event => ((newProxyGroup.value.icon) = $event)),
                              label: "icon",
                              clearable: "",
                              hint: "在 api 返回icon所输入的字符串"
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    }),
                    _createVNode(_component_v_row, null, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value.interval,
                              "onUpdate:modelValue": _cache[48] || (_cache[48] = $event => ((newProxyGroup.value.interval) = $event)),
                              modelModifiers: { number: true },
                              label: "interval",
                              variant: "outlined",
                              type: "number",
                              min: "0",
                              suffix: "秒",
                              hint: "健康检查间隔，如不为 0 则启用定时测试",
                              rules: [v => v > -1 || '检查间隔需不小于0']
                            }, {
                              "prepend-inner": _withCtx(() => [
                                _createVNode(_component_v_icon, { color: "warning" }, {
                                  default: _withCtx(() => _cache[221] || (_cache[221] = [
                                    _createTextVNode("mdi-timer")
                                  ])),
                                  _: 1
                                })
                              ]),
                              _: 1
                            }, 8, ["modelValue", "rules"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value.timeout,
                              "onUpdate:modelValue": _cache[49] || (_cache[49] = $event => ((newProxyGroup.value.timeout) = $event)),
                              modelModifiers: { number: true },
                              label: "timeout",
                              variant: "outlined",
                              type: "number",
                              min: "1",
                              hint: "请求的超时时间",
                              suffix: "毫秒",
                              rules: [v => v > 0 || '超时时间必须大于0']
                            }, {
                              "prepend-inner": _withCtx(() => [
                                _createVNode(_component_v_icon, { color: "warning" }, {
                                  default: _withCtx(() => _cache[222] || (_cache[222] = [
                                    _createTextVNode("mdi-timer")
                                  ])),
                                  _: 1
                                })
                              ]),
                              _: 1
                            }, 8, ["modelValue", "rules"])
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    }),
                    _createVNode(_component_v_row, null, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_text_field, {
                              modelValue: newProxyGroup.value['max-failed-times'],
                              "onUpdate:modelValue": _cache[50] || (_cache[50] = $event => ((newProxyGroup.value['max-failed-times']) = $event)),
                              modelModifiers: { number: true },
                              label: "max-failed-times",
                              variant: "outlined",
                              type: "number",
                              min: "0",
                              hint: "最大失败次数",
                              rules: [v => v >= 0 || '最大失败次数必须大于等于0']
                            }, null, 8, ["modelValue", "rules"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_switch, {
                              modelValue: newProxyGroup.value['lazy'],
                              "onUpdate:modelValue": _cache[51] || (_cache[51] = $event => ((newProxyGroup.value['lazy']) = $event)),
                              label: "lazy",
                              inset: "",
                              hint: "未选择到当前策略组时，不进行测试",
                              "persistent-hint": ""
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_switch, {
                              modelValue: newProxyGroup.value['disable-udp'],
                              "onUpdate:modelValue": _cache[52] || (_cache[52] = $event => ((newProxyGroup.value['disable-udp']) = $event)),
                              label: "disable-udp",
                              inset: "",
                              hint: "禁用该策略组的UDP",
                              "persistent-hint": ""
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_switch, {
                              modelValue: newProxyGroup.value.hidden,
                              "onUpdate:modelValue": _cache[53] || (_cache[53] = $event => ((newProxyGroup.value.hidden) = $event)),
                              label: "hidden",
                              inset: "",
                              hint: "在 api 返回hidden状态",
                              "persistent-hint": ""
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    }),
                    _createVNode(_component_v_row, null, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_switch, {
                              modelValue: newProxyGroup.value['include-all'],
                              "onUpdate:modelValue": _cache[54] || (_cache[54] = $event => ((newProxyGroup.value['include-all']) = $event)),
                              label: "include-all",
                              inset: "",
                              hint: "引入所有出站代理以及代理集合",
                              "persistent-hint": ""
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_switch, {
                              modelValue: newProxyGroup.value['include-all-proxies'],
                              "onUpdate:modelValue": _cache[55] || (_cache[55] = $event => ((newProxyGroup.value['include-all-proxies']) = $event)),
                              label: "include-all-proxies",
                              inset: "",
                              hint: "引入所有出站代理",
                              "persistent-hint": ""
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    }),
                    (newProxyGroup.value.type === 'smart')
                      ? (_openBlock(), _createBlock(_component_v_row, { key: 3 }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_col, {
                              cols: "12",
                              md: "6"
                            }, {
                              default: _withCtx(() => [
                                _createVNode(_component_v_switch, {
                                  modelValue: newProxyGroup.value['uselightgbm'],
                                  "onUpdate:modelValue": _cache[56] || (_cache[56] = $event => ((newProxyGroup.value['uselightgbm']) = $event)),
                                  label: "uselightgbm",
                                  inset: "",
                                  hint: "使用LightGBM进行权重预测",
                                  "persistent-hint": ""
                                }, null, 8, ["modelValue"])
                              ]),
                              _: 1
                            }),
                            _createVNode(_component_v_col, {
                              cols: "12",
                              md: "6"
                            }, {
                              default: _withCtx(() => [
                                _createVNode(_component_v_switch, {
                                  modelValue: newProxyGroup.value['collectdata'],
                                  "onUpdate:modelValue": _cache[57] || (_cache[57] = $event => ((newProxyGroup.value['collectdata']) = $event)),
                                  label: "collectdata",
                                  inset: "",
                                  hint: "收集数据进行模型训练",
                                  "persistent-hint": ""
                                }, null, 8, ["modelValue"])
                              ]),
                              _: 1
                            })
                          ]),
                          _: 1
                        }))
                      : _createCommentVNode("", true)
                  ]),
                  _: 1
                }),
                _createVNode(_component_v_alert, {
                  type: "info",
                  text: "",
                  variant: "tonal"
                }, {
                  default: _withCtx(() => _cache[223] || (_cache[223] = [
                    _createTextVNode(" 参考"),
                    _createElementVNode("a", {
                      href: "https://wiki.metacubex.one/config/proxy-groups/",
                      target: "_blank",
                      style: {"text-decoration":"underline"}
                    }, "Docs", -1)
                  ])),
                  _: 1
                }),
                _createVNode(_component_v_card_actions, null, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_spacer),
                    _createVNode(_component_v_btn, {
                      color: "secondary",
                      onClick: _cache[58] || (_cache[58] = $event => (proxyGroupDialog.value = false))
                    }, {
                      default: _withCtx(() => _cache[224] || (_cache[224] = [
                        _createTextVNode("取消")
                      ])),
                      _: 1
                    }),
                    _createVNode(_component_v_btn, {
                      color: "primary",
                      type: "submit",
                      loading: saveProxyGroupLoading.value
                    }, {
                      default: _withCtx(() => _cache[225] || (_cache[225] = [
                        _createTextVNode("保存 ")
                      ])),
                      _: 1
                    }, 8, ["loading"])
                  ]),
                  _: 1
                })
              ]),
              _: 1
            })
          ]),
          _: 1
        }, 512)
      ]),
      _: 1
    }, 8, ["modelValue"]),
    _createVNode(_component_v_dialog, {
      modelValue: yamlDialog.value,
      "onUpdate:modelValue": _cache[63] || (_cache[63] = $event => ((yamlDialog).value = $event)),
      "max-width": "40rem"
    }, {
      default: _withCtx(() => [
        _createVNode(_component_v_card, null, {
          default: _withCtx(() => [
            _createVNode(_component_v_card_title, { class: "headline" }, {
              default: _withCtx(() => _cache[226] || (_cache[226] = [
                _createTextVNode("YAML 配置")
              ])),
              _: 1
            }),
            _createVNode(_component_v_card_text, { style: {"max-height":"600px","overflow-y":"auto"} }, {
              default: _withCtx(() => [
                _createVNode(_unref(VAceEditor), {
                  value: displayedYaml.value,
                  "onUpdate:value": _cache[60] || (_cache[60] = $event => ((displayedYaml).value = $event)),
                  lang: "yaml",
                  theme: "monokai",
                  options: readOnlyEditorOptions,
                  placeholder: rulesPlaceholder.value,
                  style: {"height":"30rem","width":"100%","margin-bottom":"16px"}
                }, null, 8, ["value", "placeholder"])
              ]),
              _: 1
            }),
            _createVNode(_component_v_card_actions, null, {
              default: _withCtx(() => [
                _createVNode(_component_v_spacer),
                _createVNode(_component_v_btn, {
                  color: "primary",
                  onClick: _cache[61] || (_cache[61] = $event => (copyToClipboard(displayedYaml.value)))
                }, {
                  default: _withCtx(() => _cache[227] || (_cache[227] = [
                    _createTextVNode("复制")
                  ])),
                  _: 1
                }),
                _createVNode(_component_v_btn, {
                  color: "primary",
                  onClick: _cache[62] || (_cache[62] = $event => (yamlDialog.value = false))
                }, {
                  default: _withCtx(() => _cache[228] || (_cache[228] = [
                    _createTextVNode("关闭")
                  ])),
                  _: 1
                })
              ]),
              _: 1
            })
          ]),
          _: 1
        })
      ]),
      _: 1
    }, 8, ["modelValue"]),
    _createVNode(_component_v_dialog, {
      modelValue: importRuleDialog.value,
      "onUpdate:modelValue": _cache[67] || (_cache[67] = $event => ((importRuleDialog).value = $event)),
      "max-width": "40rem"
    }, {
      default: _withCtx(() => [
        _createVNode(_component_v_card, null, {
          default: _withCtx(() => [
            _createVNode(_component_v_card_title, null, {
              default: _withCtx(() => _cache[229] || (_cache[229] = [
                _createTextVNode("导入规则")
              ])),
              _: 1
            }),
            _createVNode(_component_v_card_text, { style: {"max-height":"900px","overflow-y":"auto"} }, {
              default: _withCtx(() => [
                _createVNode(_component_v_select, {
                  modelValue: importRules.value.type,
                  "onUpdate:modelValue": _cache[64] || (_cache[64] = $event => ((importRules.value.type) = $event)),
                  items: importRuleTypes,
                  label: "内容格式",
                  required: "",
                  class: "mb-4"
                }, null, 8, ["modelValue"]),
                _createVNode(_unref(VAceEditor), {
                  value: importRules.value.payload,
                  "onUpdate:value": _cache[65] || (_cache[65] = $event => ((importRules.value.payload) = $event)),
                  lang: "yaml",
                  theme: "monokai",
                  options: editorOptions,
                  placeholder: rulesPlaceholder.value,
                  style: {"height":"30rem","width":"100%","margin-bottom":"16px"}
                }, null, 8, ["value", "placeholder"]),
                _createVNode(_component_v_alert, {
                  type: "info",
                  dense: "",
                  text: "",
                  class: "mb-4",
                  variant: "tonal"
                }, {
                  default: _withCtx(() => _cache[230] || (_cache[230] = [
                    _createTextVNode(" 请输入 Clash 规则中的 "),
                    _createElementVNode("strong", null, "rules", -1),
                    _createTextVNode(" 字段，例如："),
                    _createElementVNode("br", null, null, -1),
                    _createElementVNode("code", null, [
                      _createTextVNode("rules:"),
                      _createElementVNode("br"),
                      _createTextVNode("- DOMAIN,gemini.google.com,Openai")
                    ], -1)
                  ])),
                  _: 1
                })
              ]),
              _: 1
            }),
            _createVNode(_component_v_card_actions, null, {
              default: _withCtx(() => [
                _createVNode(_component_v_spacer),
                _createVNode(_component_v_btn, {
                  color: "secondary",
                  onClick: _cache[66] || (_cache[66] = $event => (importRuleDialog.value = false))
                }, {
                  default: _withCtx(() => _cache[231] || (_cache[231] = [
                    _createTextVNode("取消")
                  ])),
                  _: 1
                }),
                _createVNode(_component_v_btn, {
                  color: "primary",
                  onClick: importRule,
                  loading: importRuleLoading.value
                }, {
                  default: _withCtx(() => _cache[232] || (_cache[232] = [
                    _createTextVNode("导入 ")
                  ])),
                  _: 1
                }, 8, ["loading"])
              ]),
              _: 1
            })
          ]),
          _: 1
        })
      ]),
      _: 1
    }, 8, ["modelValue"]),
    _createVNode(_component_v_dialog, {
      modelValue: importExtraProxiesDialog.value,
      "onUpdate:modelValue": _cache[72] || (_cache[72] = $event => ((importExtraProxiesDialog).value = $event)),
      "max-width": "40rem"
    }, {
      default: _withCtx(() => [
        _createVNode(_component_v_card, null, {
          default: _withCtx(() => [
            _createVNode(_component_v_card_title, null, {
              default: _withCtx(() => _cache[233] || (_cache[233] = [
                _createTextVNode("导入节点")
              ])),
              _: 1
            }),
            _createVNode(_component_v_card_text, { style: {"max-height":"900px","overflow-y":"auto"} }, {
              default: _withCtx(() => [
                _createVNode(_component_v_select, {
                  modelValue: importExtraProxies.value.type,
                  "onUpdate:modelValue": _cache[68] || (_cache[68] = $event => ((importExtraProxies.value.type) = $event)),
                  items: importProxiesTypes,
                  label: "内容格式",
                  required: "",
                  class: "mb-4"
                }, null, 8, ["modelValue"]),
                (importExtraProxies.value.type === 'YAML')
                  ? (_openBlock(), _createBlock(_unref(VAceEditor), {
                      key: 0,
                      value: importExtraProxies.value.payload,
                      "onUpdate:value": _cache[69] || (_cache[69] = $event => ((importExtraProxies.value.payload) = $event)),
                      lang: "yaml",
                      theme: "monokai",
                      options: editorOptions,
                      placeholder: proxiesPlaceholder.value,
                      style: {"height":"30rem","width":"100%","margin-bottom":"16px"}
                    }, null, 8, ["value", "placeholder"]))
                  : (_openBlock(), _createBlock(_component_v_textarea, {
                      key: 1,
                      modelValue: importExtraProxies.value.payload,
                      "onUpdate:modelValue": _cache[70] || (_cache[70] = $event => ((importExtraProxies.value.payload) = $event)),
                      label: "内容",
                      required: "",
                      placeholder: importExtraProxiesPlaceholderText.value,
                      class: "mb-4",
                      rows: "4",
                      "auto-grow": ""
                    }, null, 8, ["modelValue", "placeholder"])),
                (importExtraProxies.value.type === 'YAML')
                  ? (_openBlock(), _createBlock(_component_v_alert, {
                      key: 2,
                      type: "info",
                      dense: "",
                      text: "",
                      variant: "tonal"
                    }, {
                      default: _withCtx(() => _cache[234] || (_cache[234] = [
                        _createTextVNode(" 请输入 Clash 规则中的 "),
                        _createElementVNode("strong", null, "proxies", -1),
                        _createTextVNode(" 字段，例如："),
                        _createElementVNode("br", null, null, -1),
                        _createElementVNode("pre", { style: {"white-space":"pre-wrap","font-family":"monospace","margin":"0"} }, [
                          _createTextVNode(""),
                          _createElementVNode("code", null, "proxies:\n  - name: \"ss node\"\n    type: \"ss\"")
                        ], -1)
                      ])),
                      _: 1
                    }))
                  : _createCommentVNode("", true),
                (importExtraProxies.value.type === 'LINK')
                  ? (_openBlock(), _createBlock(_component_v_alert, {
                      key: 3,
                      type: "info",
                      dense: "",
                      text: "",
                      variant: "tonal"
                    }, {
                      default: _withCtx(() => _cache[235] || (_cache[235] = [
                        _createTextVNode(" 请输入 V2RayN 格式的分享链接，例如："),
                        _createElementVNode("br", null, null, -1),
                        _createElementVNode("code", null, "vmess://xxxx", -1),
                        _createElementVNode("br", null, null, -1),
                        _createElementVNode("code", null, "ss://xxxx", -1)
                      ])),
                      _: 1
                    }))
                  : _createCommentVNode("", true)
              ]),
              _: 1
            }),
            _createVNode(_component_v_card_actions, null, {
              default: _withCtx(() => [
                _createVNode(_component_v_spacer),
                _createVNode(_component_v_btn, {
                  color: "secondary",
                  onClick: _cache[71] || (_cache[71] = $event => (importExtraProxiesDialog.value=false))
                }, {
                  default: _withCtx(() => _cache[236] || (_cache[236] = [
                    _createTextVNode("取消")
                  ])),
                  _: 1
                }),
                _createVNode(_component_v_btn, {
                  color: "primary",
                  onClick: importExtraProxiesFun,
                  loading: importProxiesLoading.value
                }, {
                  default: _withCtx(() => _cache[237] || (_cache[237] = [
                    _createTextVNode(" 导入 ")
                  ])),
                  _: 1
                }, 8, ["loading"])
              ]),
              _: 1
            })
          ]),
          _: 1
        })
      ]),
      _: 1
    }, 8, ["modelValue"]),
    _createVNode(_component_v_dialog, {
      modelValue: ruleProviderDialog.value,
      "onUpdate:modelValue": _cache[83] || (_cache[83] = $event => ((ruleProviderDialog).value = $event)),
      "max-width": "40rem"
    }, {
      default: _withCtx(() => [
        _createVNode(_component_v_form, {
          ref_key: "ruleProvidersForm",
          ref: ruleProvidersForm,
          onSubmit: _withModifiers(saveRuleProvider, ["prevent"])
        }, {
          default: _withCtx(() => [
            _createVNode(_component_v_card, null, {
              default: _withCtx(() => [
                _createVNode(_component_v_card_title, null, {
                  default: _withCtx(() => [
                    _createTextVNode(_toDisplayString(editingRuleProviderName.value === null ? '添加规则集合' : '编辑规则集合'), 1)
                  ]),
                  _: 1
                }),
                _createVNode(_component_v_card_text, null, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_text_field, {
                      modelValue: newRuleProvider.value.name,
                      "onUpdate:modelValue": _cache[73] || (_cache[73] = $event => ((newRuleProvider.value.name) = $event)),
                      label: "name",
                      required: "",
                      rules: [v => !!v || '名称不能为空'],
                      class: "mb-4"
                    }, null, 8, ["modelValue", "rules"]),
                    _createVNode(_component_v_select, {
                      modelValue: newRuleProvider.value.type,
                      "onUpdate:modelValue": _cache[74] || (_cache[74] = $event => ((newRuleProvider.value.type) = $event)),
                      items: ruleProviderTypes,
                      label: "type",
                      required: "",
                      rules: [v => !!v || '类型不能为空'],
                      class: "mb-4"
                    }, null, 8, ["modelValue", "rules"]),
                    (newRuleProvider.value.type === 'http')
                      ? (_openBlock(), _createBlock(_component_v_text_field, {
                          key: 0,
                          modelValue: newRuleProvider.value.url,
                          "onUpdate:modelValue": _cache[75] || (_cache[75] = $event => ((newRuleProvider.value.url) = $event)),
                          label: "url",
                          required: "",
                          rules: [(v) => !!v || 'URL 不能为空', (v) => isValidUrl(v) || '请输入有效的 URL',],
                          class: "mb-4",
                          hint: "当类型为 http 时必须配置"
                        }, null, 8, ["modelValue", "rules"]))
                      : _createCommentVNode("", true),
                    (newRuleProvider.value.type === 'file')
                      ? (_openBlock(), _createBlock(_component_v_text_field, {
                          key: 1,
                          modelValue: newRuleProvider.value.path,
                          "onUpdate:modelValue": _cache[76] || (_cache[76] = $event => ((newRuleProvider.value.path) = $event)),
                          label: "path",
                          required: "",
                          rules: [v => !!v || '当类型为文件时，路径不能为空'],
                          class: "mb-4",
                          hint: "文件路径，不填写时会使用 url 的 MD5 作为文件名"
                        }, null, 8, ["modelValue", "rules"]))
                      : _createCommentVNode("", true),
                    _createVNode(_component_v_text_field, {
                      modelValue: newRuleProvider.value.interval,
                      "onUpdate:modelValue": _cache[77] || (_cache[77] = $event => ((newRuleProvider.value.interval) = $event)),
                      modelModifiers: { number: true },
                      label: "interval",
                      class: "mb-4",
                      type: "number",
                      min: "0",
                      suffix: "秒",
                      hint: "Provider 的更新间隔",
                      rules: [v => (v === null || v === undefined || v >= 0) || '更新间隔不能为负数']
                    }, null, 8, ["modelValue", "rules"]),
                    _createVNode(_component_v_select, {
                      modelValue: newRuleProvider.value.behavior,
                      "onUpdate:modelValue": _cache[78] || (_cache[78] = $event => ((newRuleProvider.value.behavior) = $event)),
                      items: ruleProviderBehaviorTypes,
                      label: "behavior",
                      class: "mb-4",
                      hint: "对应不同格式的 rule-provider 文件"
                    }, null, 8, ["modelValue"]),
                    _createVNode(_component_v_select, {
                      modelValue: newRuleProvider.value.format,
                      "onUpdate:modelValue": _cache[79] || (_cache[79] = $event => ((newRuleProvider.value.format) = $event)),
                      items: ruleProviderFormatTypes,
                      label: "format",
                      class: "mb-4",
                      hint: "mrs目前 behavior 仅支持 domain/ipcidr"
                    }, null, 8, ["modelValue"]),
                    _createVNode(_component_v_text_field, {
                      modelValue: newRuleProvider.value['size-limit'],
                      "onUpdate:modelValue": _cache[80] || (_cache[80] = $event => ((newRuleProvider.value['size-limit']) = $event)),
                      modelModifiers: { number: true },
                      label: "size-limit",
                      class: "mb-4",
                      type: "number",
                      min: "0",
                      suffix: "byte(s)",
                      hint: "可下载文件的最大大小，0 表示无限制",
                      rules: [v => (v === null || v === undefined || v >= 0) || '大小限制不能为负数']
                    }, null, 8, ["modelValue", "rules"]),
                    (newRuleProvider.value.type === 'inline')
                      ? (_openBlock(), _createBlock(_component_v_combobox, {
                          key: 2,
                          modelValue: newRuleProvider.value.payload,
                          "onUpdate:modelValue": _cache[81] || (_cache[81] = $event => ((newRuleProvider.value.payload) = $event)),
                          multiple: "",
                          chips: "",
                          "closable-chips": "",
                          clearable: "",
                          label: "payload",
                          required: "",
                          rules: [v => !!v || '当类型为 inline 时，内容不能为空'],
                          class: "mb-4",
                          hint: "当类型为 inline 时才有效，按回车确认输入",
                          row: ""
                        }, {
                          chip: _withCtx(({ props, item }) => [
                            _createVNode(_component_v_chip, _mergeProps(props, {
                              closable: "",
                              size: "small"
                            }), {
                              default: _withCtx(() => [
                                _createTextVNode(_toDisplayString(item.value), 1)
                              ]),
                              _: 2
                            }, 1040)
                          ]),
                          _: 1
                        }, 8, ["modelValue", "rules"]))
                      : _createCommentVNode("", true)
                  ]),
                  _: 1
                }),
                _createVNode(_component_v_card_actions, null, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_spacer),
                    _createVNode(_component_v_btn, {
                      color: "secondary",
                      onClick: _cache[82] || (_cache[82] = $event => (ruleProviderDialog.value = false))
                    }, {
                      default: _withCtx(() => _cache[238] || (_cache[238] = [
                        _createTextVNode("取消")
                      ])),
                      _: 1
                    }),
                    _createVNode(_component_v_btn, {
                      color: "primary",
                      type: "submit",
                      loading: saveRuleProviderLoading.value
                    }, {
                      default: _withCtx(() => _cache[239] || (_cache[239] = [
                        _createTextVNode("保存 ")
                      ])),
                      _: 1
                    }, 8, ["loading"])
                  ]),
                  _: 1
                })
              ]),
              _: 1
            })
          ]),
          _: 1
        }, 512)
      ]),
      _: 1
    }, 8, ["modelValue"]),
    _createVNode(_component_v_dialog, {
      modelValue: hostDialog.value,
      "onUpdate:modelValue": _cache[88] || (_cache[88] = $event => ((hostDialog).value = $event)),
      "max-width": "40rem"
    }, {
      default: _withCtx(() => [
        _createVNode(_component_v_form, {
          ref_key: "hostForm",
          ref: hostForm,
          onSubmit: _withModifiers(saveHost, ["prevent"])
        }, {
          default: _withCtx(() => [
            _createVNode(_component_v_card, null, {
              default: _withCtx(() => [
                _createVNode(_component_v_card_title, null, {
                  default: _withCtx(() => [
                    _createTextVNode(_toDisplayString(editingHostDomainName.value === null ? '添加 Host' : '编辑 Host'), 1)
                  ]),
                  _: 1
                }),
                _createVNode(_component_v_card_text, null, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_text_field, {
                      modelValue: newHost.value.domain,
                      "onUpdate:modelValue": _cache[84] || (_cache[84] = $event => ((newHost.value.domain) = $event)),
                      label: "域名",
                      required: "",
                      rules: [v => !!v || '域名不能为空'],
                      class: "mb-4"
                    }, null, 8, ["modelValue", "rules"]),
                    (!newHost.value.using_cloudflare)
                      ? (_openBlock(), _createBlock(_component_v_combobox, {
                          key: 0,
                          modelValue: newHost.value.value,
                          "onUpdate:modelValue": _cache[85] || (_cache[85] = $event => ((newHost.value.value) = $event)),
                          multiple: "",
                          chips: "",
                          "closable-chips": "",
                          clearable: "",
                          label: "IP",
                          required: "",
                          rules: [validateIPs],
                          class: "mb-4",
                          hint: "一个或多个 IP 地址"
                        }, {
                          chip: _withCtx(({ props, item }) => [
                            _createVNode(_component_v_chip, _mergeProps(props, {
                              closable: "",
                              size: "small"
                            }), {
                              default: _withCtx(() => [
                                _createTextVNode(_toDisplayString(item.value), 1)
                              ]),
                              _: 2
                            }, 1040)
                          ]),
                          _: 1
                        }, 8, ["modelValue", "rules"]))
                      : _createCommentVNode("", true),
                    _createVNode(_component_v_row, null, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_col, {
                          cols: "12",
                          md: "6"
                        }, {
                          default: _withCtx(() => [
                            _createVNode(_component_v_switch, {
                              modelValue: newHost.value.using_cloudflare,
                              "onUpdate:modelValue": _cache[86] || (_cache[86] = $event => ((newHost.value.using_cloudflare) = $event)),
                              label: "使用 Cloudflare CDN",
                              inset: "",
                              hint: "设置为 CF 优选 IPs",
                              "persistent-hint": ""
                            }, null, 8, ["modelValue"])
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    })
                  ]),
                  _: 1
                }),
                (bestCloudflareIPs.value.length === 0 && newHost.value.using_cloudflare)
                  ? (_openBlock(), _createBlock(_component_v_alert, {
                      key: 0,
                      type: "warning",
                      text: "",
                      variant: "outlined",
                      class: "mb-2"
                    }, {
                      default: _withCtx(() => _cache[240] || (_cache[240] = [
                        _createTextVNode(" 请在「高级选项」配置 Cloudflare CDN 优选 IPs ")
                      ])),
                      _: 1
                    }))
                  : _createCommentVNode("", true),
                _createVNode(_component_v_alert, {
                  type: "info",
                  text: "",
                  variant: "tonal"
                }, {
                  default: _withCtx(() => _cache[241] || (_cache[241] = [
                    _createTextVNode(" 支持"),
                    _createElementVNode("a", {
                      href: "https://wiki.metacubex.one/handbook/syntax/#_8",
                      target: "_blank"
                    }, "域名通配符", -1)
                  ])),
                  _: 1
                }),
                _createVNode(_component_v_card_actions, null, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_spacer),
                    _createVNode(_component_v_btn, {
                      color: "secondary",
                      onClick: _cache[87] || (_cache[87] = $event => (hostDialog.value = false))
                    }, {
                      default: _withCtx(() => _cache[242] || (_cache[242] = [
                        _createTextVNode("取消")
                      ])),
                      _: 1
                    }),
                    _createVNode(_component_v_btn, {
                      color: "primary",
                      type: "submit",
                      loading: saveHostLoading.value
                    }, {
                      default: _withCtx(() => _cache[243] || (_cache[243] = [
                        _createTextVNode("保存 ")
                      ])),
                      _: 1
                    }, 8, ["loading"])
                  ]),
                  _: 1
                })
              ]),
              _: 1
            })
          ]),
          _: 1
        }, 512)
      ]),
      _: 1
    }, 8, ["modelValue"]),
    (proxiesDialogVisible.value)
      ? (_openBlock(), _createBlock(ProxiesDialog, {
          key: 1,
          modelValue: proxiesDialogVisible.value,
          "onUpdate:modelValue": _cache[89] || (_cache[89] = $event => ((proxiesDialogVisible).value = $event)),
          "proxy-data": editingProxy.value,
          loading: saveProxyLoading.value,
          onSave: saveProxy
        }, null, 8, ["modelValue", "proxy-data", "loading"]))
      : _createCommentVNode("", true)
  ]))
}
}

};
const PageComponent = /*#__PURE__*/_export_sfc(_sfc_main, [['__scopeId',"data-v-7a29c1ce"]]);

export { PageComponent as default };
